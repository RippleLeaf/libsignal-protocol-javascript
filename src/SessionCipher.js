function SessionCipher(storage, remoteAddress) {
  this.remoteAddress = remoteAddress;
  this.storage = storage;
}

SessionCipher.prototype = {
  getRecord: function(encodedNumber) {
      return this.storage.loadSession(encodedNumber).then(function(serialized) {
          if (serialized === undefined) {
              return undefined;
          }
          return Internal.SessionRecord.deserialize(serialized);
      });
  },
  encrypt: function(buffer, encoding) {
    plainByteBuffer = dcodeIO.ByteBuffer.wrap(buffer, encoding);
    buffer = plainByteBuffer.toArrayBuffer();
    var ctrBuffer = plainByteBuffer.prepend(
          new ArrayBuffer(Internal.crypto.signKeyLength*2)).toArrayBuffer();
    return Internal.SessionLock.queueJobForNumber(this.remoteAddress.toString(), function() {
      if (!(buffer instanceof ArrayBuffer)) {
          throw new Error("Expected buffer to be an ArrayBuffer");
      }

      var address = this.remoteAddress.toString();
      var ourIdentityKey, myRegistrationId, record, session, chain;

      var msg = new Internal.protobuf.WhisperMessage();

      return Promise.all([
          this.storage.getIdentityKeyPair(),
          this.storage.getLocalRegistrationId(),
          this.getRecord(address)
      ]).then(function(results) {
          ourIdentityKey   = results[0];
          myRegistrationId = results[1];
          record           = results[2];
          if (!record) {
              throw new Error("No record for " + address);
          }
          session = record.getOpenSession();
          if (!session) {
              throw new Error("No session to encrypt message for " + address);
          }

          msg.ephemeralKey = util.toArrayBuffer(
              session.currentRatchet.ephemeralKeyPair.pubKey
          );
          chain = session[util.toString(msg.ephemeralKey)];
          if (chain.chainType === Internal.ChainType.RECEIVING) {
              throw new Error("Tried to encrypt on a receiving chain");
          }

          return this.fillMessageKeys(chain, chain.chainKey.counter + 1);
      }.bind(this)).then(function() {
          return Internal.HKDF(
              util.toArrayBuffer(chain.messageKeys[chain.chainKey.counter]),
              new ArrayBuffer(32), "WhisperMessageKeys");
      }).then(function(keys) {
          delete chain.messageKeys[chain.chainKey.counter];
          msg.counter = chain.chainKey.counter;
          msg.previousCounter = session.currentRatchet.previousCounter;
          return Internal.crypto.encryptAesCtr(
              keys[0], ctrBuffer, keys[2].slice(0, 16)
          ).then(function(ciphertext) {
              // CTR mode, add 2 more blocks as keys.
              var commitKey = ciphertext.slice(0, Internal.crypto.signKeyLength);
              var macKey = ciphertext.slice(Internal.crypto.signKeyLength, Internal.crypto.signKeyLength*2);
              msg.ciphertext = ciphertext.slice(Internal.crypto.signKeyLength*2);
              var encodedMsg = msg.toArrayBuffer();

              var macInput = new Uint8Array(encodedMsg.byteLength + 33*2 + 1);
              macInput.set(new Uint8Array(util.toArrayBuffer(ourIdentityKey.pubKey)));
              macInput.set(new Uint8Array(util.toArrayBuffer(session.indexInfo.remoteIdentityKey)), 33);
              macInput[33*2] = (3 << 4) | 3;
              macInput.set(new Uint8Array(encodedMsg), 33*2 + 1);
              return Internal.crypto.sign(commitKey, macInput.buffer).then(function(commitment) {
                  return Promise.all([Internal.crypto.sign(macKey, commitment), commitment]);
              }).then(function (tags){
                  var mac = tags[0], commitment = tags[1];
                  // cipher format is [version (1), ciphertext (bytes), tag (32), commitment: 32]
                  var result = new Uint8Array(encodedMsg.byteLength + 1 + Internal.crypto.signKeyLength*2);
                  result[0] = (3 << 4) | 3;
                  result.set(new Uint8Array(encodedMsg), 1);
                  result.set(new Uint8Array(mac), encodedMsg.byteLength + 1);
                  result.set(new Uint8Array(commitment),
                        encodedMsg.byteLength + 1 + Internal.crypto.signKeyLength);

                  return this.storage.isTrustedIdentity(
                      this.remoteAddress.getName(), util.toArrayBuffer(session.indexInfo.remoteIdentityKey), this.storage.Direction.SENDING
                  ).then(function(trusted) {
                      if (!trusted) {
                          throw new Error('Identity key changed');
                      }
                  }).then(function() {
                      return this.storage.saveIdentity(this.remoteAddress.toString(), session.indexInfo.remoteIdentityKey);
                  }.bind(this)).then(function() {
                      record.updateSessionState(session);
                      return this.storage.storeSession(address, record.serialize()).then(function() {
                          return result;
                      });
                  }.bind(this));
              }.bind(this));
          }.bind(this));
      }.bind(this)).then(function(message) {
          if (session.pendingPreKey !== undefined) {
              var preKeyMsg = new Internal.protobuf.PreKeyWhisperMessage();
              preKeyMsg.identityKey = util.toArrayBuffer(ourIdentityKey.pubKey);
              preKeyMsg.registrationId = myRegistrationId;

              preKeyMsg.baseKey = util.toArrayBuffer(session.pendingPreKey.baseKey);
              if (session.pendingPreKey.preKeyId) {
                  preKeyMsg.preKeyId = session.pendingPreKey.preKeyId;
              }
              preKeyMsg.signedPreKeyId = session.pendingPreKey.signedKeyId;

              preKeyMsg.message = message;
              var result = String.fromCharCode((3 << 4) | 3) + util.toString(preKeyMsg.encode());
              return {
                  type           : 3,
                  body           : result,
                  registrationId : session.registrationId
              };

          } else {
              return {
                  type           : 1,
                  body           : util.toString(message),
                  registrationId : session.registrationId
              };
          }
      });
    }.bind(this));
  },
  decryptWithSessionList: function(buffer, sessionList, errors) {
    // Iterate recursively through the list, attempting to decrypt
    // using each one at a time. Stop and return the result if we get
    // a valid result
    if (sessionList.length === 0) {
        return Promise.reject(errors[0]);
    }

    var session = sessionList.pop();
    return this.doDecryptWhisperMessage(buffer, session).then(function(plaintext) {
        return { plaintext: plaintext, session: session };
    }).catch(function(e) {
        if (e.name === 'MessageCounterError') {
            return Promise.reject(e);
        }

        errors.push(e);
        return this.decryptWithSessionList(buffer, sessionList, errors);
    }.bind(this));
  },
  decryptWhisperMessage: function(buffer, encoding) {
      buffer = dcodeIO.ByteBuffer.wrap(buffer, encoding).toArrayBuffer();
      return Internal.SessionLock.queueJobForNumber(this.remoteAddress.toString(), function() {
        var address = this.remoteAddress.toString();
        return this.getRecord(address).then(function(record) {
            if (!record) {
                throw new Error("No record for device " + address);
            }
            var errors = [];
            return this.decryptWithSessionList(buffer, record.getSessions(), errors).then(function(result) {
                return this.getRecord(address).then(function(record) {
                    if (result.session.indexInfo.baseKey !== record.getOpenSession().indexInfo.baseKey) {
                      record.archiveCurrentState();
                      record.promoteState(result.session);
                    }

                    return this.storage.isTrustedIdentity(
                        this.remoteAddress.getName(), util.toArrayBuffer(result.session.indexInfo.remoteIdentityKey), this.storage.Direction.RECEIVING
                    ).then(function(trusted) {
                        if (!trusted) {
                            throw new Error('Identity key changed');
                        }
                    }).then(function() {
                        return this.storage.saveIdentity(this.remoteAddress.toString(), result.session.indexInfo.remoteIdentityKey);
                    }.bind(this)).then(function() {
                        record.updateSessionState(result.session);
                        return this.storage.storeSession(address, record.serialize()).then(function() {
                            return result.plaintext;
                        });
                    }.bind(this));
                }.bind(this));
            }.bind(this));
        }.bind(this));
      }.bind(this));
  },
  decryptPreKeyWhisperMessage: function(buffer, encoding) {
      buffer = dcodeIO.ByteBuffer.wrap(buffer, encoding);
      var version = buffer.readUint8();
      if ((version & 0xF) > 3 || (version >> 4) < 3) {  // min version > 3 or max version < 3
          throw new Error("Incompatible version number on PreKeyWhisperMessage");
      }
      return Internal.SessionLock.queueJobForNumber(this.remoteAddress.toString(), function() {
          var address = this.remoteAddress.toString();
          return this.getRecord(address).then(function(record) {
              var preKeyProto = Internal.protobuf.PreKeyWhisperMessage.decode(buffer);
              if (!record) {
                  if (preKeyProto.registrationId === undefined) {
                      throw new Error("No registrationId");
                  }
                  record = new Internal.SessionRecord(
                      preKeyProto.registrationId
                  );
              }
              var builder = new SessionBuilder(this.storage, this.remoteAddress);
              // isTrustedIdentity is called within processV3, no need to call it here
              return builder.processV3(record, preKeyProto).then(function(preKeyId) {
                  var session = record.getSessionByBaseKey(preKeyProto.baseKey);
                  return this.doDecryptWhisperMessage(
                      preKeyProto.message.toArrayBuffer(), session
                  ).then(function(plaintext) {
                      record.updateSessionState(session);
                      return this.storage.storeSession(address, record.serialize()).then(function() {
                          if (preKeyId !== undefined && preKeyId !== null) {
                              return this.storage.removePreKey(preKeyId);
                          }
                      }.bind(this)).then(function() {
                          return plaintext;
                      });
                  }.bind(this));
              }.bind(this));
          }.bind(this));
      }.bind(this));
  },
  doDecryptWhisperMessage: function(messageBytes, session) {
    if (!(messageBytes instanceof ArrayBuffer)) {
        throw new Error("Expected messageBytes to be an ArrayBuffer");
    }
    var version = (new Uint8Array(messageBytes))[0];
    if ((version & 0xF) > 3 || (version >> 4) < 3) {  // min version > 3 or max version < 3
        throw new Error("Incompatible version number on WhisperMessage");
    }
    var msgLen = messageBytes.byteLength;
    var messageProto = messageBytes.slice(1, msgLen - Internal.crypto.signKeyLength*2);
    var mac = messageBytes.slice(msgLen - Internal.crypto.signKeyLength*2, msgLen - Internal.crypto.signKeyLength);
    var commitment = messageBytes.slice(msgLen - Internal.crypto.signKeyLength);

    var message = Internal.protobuf.WhisperMessage.decode(messageProto);
    var remoteEphemeralKey = message.ephemeralKey.toArrayBuffer();

    if (session === undefined) {
        return Promise.reject(new Error("No session found to decrypt message from " + this.remoteAddress.toString()));
    }
    if (session.indexInfo.closed != -1) {
        console.log('decrypting message for closed session');
    }

    return this.maybeStepRatchet(session, remoteEphemeralKey, message.previousCounter).then(function() {
        var chain = session[util.toString(message.ephemeralKey)];
        if (chain.chainType === Internal.ChainType.SENDING) {
            throw new Error("Tried to decrypt on a sending chain");
        }

        return this.fillMessageKeys(chain, message.counter).then(function() {
            var messageKey = chain.messageKeys[message.counter];
            if (messageKey === undefined) {
                var e = new Error("Message key not found. The counter was repeated or the key was not filled.");
                e.name = 'MessageCounterError';
                throw e;
            }
            delete chain.messageKeys[message.counter];
            return Internal.HKDF(util.toArrayBuffer(messageKey), new ArrayBuffer(32), "WhisperMessageKeys");
        });
    }.bind(this)).then(function(keys) {
        var ciphertext = dcodeIO.ByteBuffer.wrap(message.ciphertext.toArrayBuffer()).
            prepend(new ArrayBuffer(Internal.crypto.signKeyLength*2)).toArrayBuffer();
        return Promise.all([
            Internal.crypto.decryptAesCtr(keys[0], ciphertext, keys[2].slice(0, 16)),
            this.storage.getIdentityKeyPair()]);
    }.bind(this)).then(function(ret) {
        delete session.pendingPreKey;
        // console.log(plaintext);
        var plaintext = ret[0], ourIdentityKey = ret[1];
        var commitKey = plaintext.slice(0, Internal.crypto.signKeyLength);
        var macKey = plaintext.slice(Internal.crypto.signKeyLength, Internal.crypto.signKeyLength*2);
        plaintext = plaintext.slice(Internal.crypto.signKeyLength*2);

        var macInput = new Uint8Array(messageProto.byteLength + 33*2 + 1);
        macInput.set(new Uint8Array(util.toArrayBuffer(session.indexInfo.remoteIdentityKey)));
        macInput.set(new Uint8Array(util.toArrayBuffer(ourIdentityKey.pubKey)), 33);
        macInput[33*2] = (3 << 4) | 3;
        
        macInput.set(new Uint8Array(messageProto), 33*2 + 1);
        return Promise.all([
            plaintext, 
            commitKey, 
            commitment,
            macInput.slice(0, 33*2 + 1),
            Internal.verifyMAC(macInput.buffer, commitKey, commitment, 32),
            Internal.verifyMAC(commitment, macKey, mac, 32)
        ]);
    }).then(function (ret){
        return {
            header: ret[3],
            body: ret[0],
            commitKey: ret[1],
            commitment: ret[2],
        };
    });
  },
  fillMessageKeys: function(chain, counter) {
      if (chain.chainKey.counter >= counter) {
          return Promise.resolve(); // Already calculated
      }

      if (counter - chain.chainKey.counter > 2000) {
          throw new Error('Over 2000 messages into the future!');
      }

      if (chain.chainKey.key === undefined) {
          throw new Error("Got invalid request to extend chain after it was already closed");
      }

      var key = util.toArrayBuffer(chain.chainKey.key);
      var byteArray = new Uint8Array(1);
      byteArray[0] = 1;
      return Internal.crypto.sign(key, byteArray.buffer).then(function(mac) {
          byteArray[0] = 2;
          return Internal.crypto.sign(key, byteArray.buffer).then(function(key) {
              chain.messageKeys[chain.chainKey.counter + 1] = mac;
              chain.chainKey.key = key;
              chain.chainKey.counter += 1;
              return this.fillMessageKeys(chain, counter);
          }.bind(this));
      }.bind(this));
  },
  maybeStepRatchet: function(session, remoteKey, previousCounter) {
      if (session[util.toString(remoteKey)] !== undefined) {
          return Promise.resolve();
      }

      console.log('New remote ephemeral key');
      var ratchet = session.currentRatchet;

      return Promise.resolve().then(function() {
          var previousRatchet = session[util.toString(ratchet.lastRemoteEphemeralKey)];
          if (previousRatchet !== undefined) {
              return this.fillMessageKeys(previousRatchet, previousCounter).then(function() {
                  delete previousRatchet.chainKey.key;
                  session.oldRatchetList[session.oldRatchetList.length] = {
                      added        : Date.now(),
                      ephemeralKey : ratchet.lastRemoteEphemeralKey
                  };
              });
          }
      }.bind(this)).then(function() {
          return this.calculateRatchet(session, remoteKey, false).then(function() {
              // Now swap the ephemeral key and calculate the new sending chain
              var previousRatchet = util.toString(ratchet.ephemeralKeyPair.pubKey);
              if (session[previousRatchet] !== undefined) {
                  ratchet.previousCounter = session[previousRatchet].chainKey.counter;
                  delete session[previousRatchet];
              }

              return Internal.crypto.createKeyPair().then(function(keyPair) {
                  ratchet.ephemeralKeyPair = keyPair;
                  return this.calculateRatchet(session, remoteKey, true).then(function() {
                      ratchet.lastRemoteEphemeralKey = remoteKey;
                  }.bind(this));
              }.bind(this));
          }.bind(this));
      }.bind(this));
  },
  calculateRatchet: function(session, remoteKey, sending) {
      var ratchet = session.currentRatchet;

      return Internal.crypto.ECDHE(remoteKey, util.toArrayBuffer(ratchet.ephemeralKeyPair.privKey)).then(function(sharedSecret) {
          return Internal.HKDF(sharedSecret, util.toArrayBuffer(ratchet.rootKey), "WhisperRatchet").then(function(masterKey) {
              var ephemeralPublicKey;
              if (sending) {
                  ephemeralPublicKey = ratchet.ephemeralKeyPair.pubKey;
              }
              else {
                  ephemeralPublicKey = remoteKey;
              }
              session[util.toString(ephemeralPublicKey)] = {
                  messageKeys: {},
                  chainKey: { counter: -1, key: masterKey[1] },
                  chainType: sending ? Internal.ChainType.SENDING : Internal.ChainType.RECEIVING
              };
              ratchet.rootKey = masterKey[0];
          });
      });
  },
  getRemoteRegistrationId: function() {
    return Internal.SessionLock.queueJobForNumber(this.remoteAddress.toString(), function() {
      return this.getRecord(this.remoteAddress.toString()).then(function(record) {
          if (record === undefined) {
              return undefined;
          }
          var openSession = record.getOpenSession();
          if (openSession === undefined) {
              return null;
          }
          return openSession.registrationId;
      });
    }.bind(this));
  },
  hasOpenSession: function() {
    return Internal.SessionLock.queueJobForNumber(this.remoteAddress.toString(), function() {
      return this.getRecord(this.remoteAddress.toString()).then(function(record) {
          if (record === undefined) {
              return false;
          }
          return record.haveOpenSession();
      });
    }.bind(this));
  },
  closeOpenSessionForDevice: function() {
    var address = this.remoteAddress.toString();
    return Internal.SessionLock.queueJobForNumber(address, function() {
      return this.getRecord(address).then(function(record) {
        if (record === undefined || record.getOpenSession() === undefined) {
            return;
        }

        record.archiveCurrentState();
        return this.storage.storeSession(address, record.serialize());
      }.bind(this));
    }.bind(this));
  },
  deleteAllSessionsForDevice: function() {
    // Used in session reset scenarios, where we really need to delete
    var address = this.remoteAddress.toString();
    return Internal.SessionLock.queueJobForNumber(address, function() {
      return this.getRecord(address).then(function(record) {
        if (record === undefined) {
            return;
        }

        record.deleteAllSessions();
        return this.storage.storeSession(address, record.serialize());
      }.bind(this));
    }.bind(this));
  }
};

libsignal.SessionCipher = function(storage, remoteAddress) {
    var cipher = new SessionCipher(storage, remoteAddress);

    // returns a Promise that resolves to a ciphertext object
    this.encrypt = cipher.encrypt.bind(cipher);

    // returns a Promise that inits a session if necessary and resolves
    // to a decrypted plaintext array buffer
    this.decryptPreKeyWhisperMessage = cipher.decryptPreKeyWhisperMessage.bind(cipher);

    // returns a Promise that resolves to decrypted plaintext array buffer
    this.decryptWhisperMessage = cipher.decryptWhisperMessage.bind(cipher);

    this.getRemoteRegistrationId = cipher.getRemoteRegistrationId.bind(cipher);
    this.hasOpenSession = cipher.hasOpenSession.bind(cipher);
    this.closeOpenSessionForDevice = cipher.closeOpenSessionForDevice.bind(cipher);
    this.deleteAllSessionsForDevice = cipher.deleteAllSessionsForDevice.bind(cipher);
};
