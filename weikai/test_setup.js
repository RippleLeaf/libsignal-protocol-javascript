
//-----------------------------------------------
// Generate User Profile, including IDs, public and private key pairs,
// and signature, which is a custom struct.
// Return Promise of User Profile.
//-----------------------------------------------
function initClient(identifier, keyId){
  var store = new SignalProtocolStore();
  var KeyHelper = libsignal.KeyHelper;
  var registrationId = KeyHelper.generateRegistrationId();
  var ret = {};
  ret.keyId = keyId;
  ret.identifier = identifier;
  var identityKeyPair;

  return KeyHelper.generateIdentityKeyPair().then(function(identityKP) { 
    ret.identityKeyPair = identityKP;
    // console.log(ret.identityKeyPair);
    store.putLocalRegistrationId(registrationId);
    store.saveIdentity(identifier, identityKP);
    store.putIdentityKeyPair(identityKP);
  }).then(function(){
    return KeyHelper.generatePreKey(keyId);
  }).then(function(preKey){
    store.storePreKey(preKey.keyId, preKey.keyPair);
  }).then(function(){
    return KeyHelper.generateSignedPreKey(ret.identityKeyPair, keyId);
  }).then(function(signedPreKey){
    keyPair = signedPreKey.keyPair;
    keyPair.signature = signedPreKey.signature;
    store.storeSignedPreKey(signedPreKey.keyId, keyPair);
    
    ret.store = store;
    ret.publicId = getPublicId(ret);
    return ret;
  });
}

//-----------------------------------------------
// Get public IDs and keys from User Profile.
// Return a struct that works as an arg to SessionBuilder.processPreKey().
//-----------------------------------------------
function getPublicId(user) {
  var userPreKey = user.store.get('25519KeypreKey' + user.keyId);
  var userSignedKey = user.store.get('25519KeysignedKey' + user.keyId);
  var userRegId = user.store.get('registrationId');
  var ret = {
    identifier: user.identifier,
    keyId: user.keyId,
    registrationId: userRegId,
    identityKey: user.identityKeyPair.pubKey,
    signedPreKey: {
      keyId: user.keyId,
      publicKey: userSignedKey.pubKey,
      signature: userSignedKey.signature,
    },
    preKey:{
      keyId: user.keyId,
      publicKey: userPreKey.pubKey,
    }
  };
  return ret;
}

function buildSession(sender, rcverId){ 
  var address = new libsignal.SignalProtocolAddress(rcverId.identifier, rcverId.keyId);
  var sessionBuilder = new libsignal.SessionBuilder(sender.store, address);
  return sessionBuilder.processPreKey(rcverId);
}

function newEncrypt(sender, rcver, plaintext) {
  var address = new libsignal.SignalProtocolAddress(rcver.identifier, rcver.keyId);
  var sessionCipher = new libsignal.SessionCipher(sender.store, address);
  sender.sessionCipher = sessionCipher;
  return sessionCipher.encrypt(plaintext);
}

function doEncrypt(sender, rcver, plaintext) {
  var address = new libsignal.SignalProtocolAddress(rcver.identifier, rcver.keyId);
  return sender.sessionCipher.encrypt(plaintext);
}

//-----------------------------------------------
// Return a struct:
// {
//     header: 'H (ArrayBuffer)',
//     body: 'M (ArrayBuffer)',
//     commitKey: 'Kf (ArrayBuffer)',
//     commitment: 'C2 (ArrayBuffer)',
// }
//-----------------------------------------------
function newDecrypt(sender, rcver, ciphertext) {
  var address = new libsignal.SignalProtocolAddress(sender.identifier, sender.keyId);
  var sessionCipher = new libsignal.SessionCipher(rcver.store, address);
  rcver.sessionCipher = sessionCipher;
  return sessionCipher.decryptPreKeyWhisperMessage(ciphertext.body, "binary").
    then(function (ret) {
        console.log(ret);
        return ret;
    });
}

function doDecrypt(sender, rcver, ciphertext) {
  var address = new libsignal.SignalProtocolAddress(sender.identifier, sender.keyId);
  return rcver.sessionCipher.decryptWhisperMessage(ciphertext.body, "binary").
    then(function (ret) {
        console.log(ret);
        return ret;
    });
}


//-----------------------------------------------
// Generate the secret key of the server
// Return Promise of server setting.
//-----------------------------------------------
function MessengerServer() {
  this.secretKey = Uint8Array.from(
          [192,106,86,38,22,204,187,56,111,79,114,168,231,35,161,164,
          183,157,252,75,64,170,31,171,79,231,209,78,242,130,15,51]);
  this.clientPublicId = {};

  this.setPublicId = function (client, publicId) {
    this.clientPublicId[client] = publicId;
  };

  this.getPublicId = function (client) {
    return this.clientPublicId[client];
  };

  this._getCommitment = function (ciphertext) {
    var buffer = dcodeIO.ByteBuffer.wrap(ciphertext.body, 'binary').toArrayBuffer();
    var msgLen = buffer.byteLength;
    return buffer.slice(msgLen - 32);
  };

  this._verifyMAC = function(data, key, mac, length) {
      return this._calcHmac(key, data).then(function(calculated_mac) {
          if (mac.byteLength != length  || calculated_mac.byteLength < length) {
              throw new Error("Bad MAC length");
          }
          var a = new Uint8Array(calculated_mac);
          var b = new Uint8Array(mac);
          var result = 0;
          for (var i=0; i < mac.byteLength; ++i) {
              result = result | (a[i] ^ b[i]);
          }
          if (result !== 0) {
              throw new Error("Bad MAC");
          }
      });
  };

  //---------------------------------------------
  // Sign (or add MAC) to cihper message, 
  // then relay both chiper message and MAC.
  //---------------------------------------------
  this.signMessage = function (ciphertext) {
    var com = this._getCommitment(ciphertext);
    return this._calcHmac(this.secretKey.buffer, com).then(function (mac) {
        ciphertext.mac = mac;
        return ciphertext;
    });
  };

  this._calcHmac = function (keyHmac, data) {
    var crypto = window.crypto;
    if (!crypto || !crypto.subtle || typeof crypto.getRandomValues !== 'function') {
        throw new Error('WebCrypto not found');
    }
    return crypto.subtle.importKey(
        'raw', keyHmac, {name: 'HMAC', hash: {name: 'SHA-256'}}, false, ['sign']).
    then(function (key) {
        return crypto.subtle.sign( {name: 'HMAC', hash: 'SHA-256'}, key, data);
    });
  };

  this.reportAbuse = function(sender, rcver, evidence, mac){
    var macInput = new Uint8Array(evidence.header.byteLength + evidence.body.byteLength);
    macInput.set(new Uint8Array(evidence.header));
    macInput.set(new Uint8Array(evidence.body), evidence.header.byteLength);
    return Promise.all([
        this._verifyMAC(evidence.commitment, this.secretKey.buffer, mac, 32),
        this._verifyMAC(macInput, evidence.commitKey, evidence.commitment, 32)
    ]);
  };

}


function MessengerClient() {
  this.userProfile;

//-----------------------------------------------
// Init client, generate IDs and keys.
// Return Promise of Public ID.
//-----------------------------------------------
  this.init = function (name, identifier, keyId) {
    return initClient(identifier, keyId).then(function (user){
        this.userProfile = user;
        this.userProfile.name = name;
        this.userProfile.handShake = [];
        console.log(this.userProfile);
        return user.publicId;
    }.bind(this));
  };

//-----------------------------------------------
// Send encrypted message. Build a new session if not exist.
// Return Promise of a ciphertext.
//-----------------------------------------------
  this.sendMessage = function (rcverId, plaintext) {
    var our = this.userProfile;
    var they = rcverId.identifier;
    // if the sender hasn't shaked hands with the rcv
    // build a new session
    if(our.handShake[they] == undefined || our.handShake[they] == false){
      our.handShake[they] = false;
      return buildSession(our, rcverId).then(function onsuccess() {
        // console.log('newEncrypt');
        return newEncrypt(our, rcverId, plaintext);
      });
    }
    else{
      // console.log('doEncrypt');
      return doEncrypt(our, rcverId, plaintext);
    }
  };

//-----------------------------------------------
// Receive encrypted message. Build a new session if not exist.
// Return Promise of a [plaintext, message ID].
//-----------------------------------------------
  this.receiveMessage = function (senderId, signedCipher) {
    var our = this.userProfile;
    var they = senderId.identifier;
    if(our.handShake[they] == undefined){
      // console.log('newDecrypt');
      our.handShake[they] = true;
      return newDecrypt(senderId, our, signedCipher).then(function (evidence) {
          var msgId = this._pushHistory(they, evidence, signedCipher.mac);
          return [evidence.body, msgId];
      }.bind(this));
    }
    else{
      our.handShake[they] = true;
      // console.log('doDecrypt');
      return doDecrypt(senderId, our, signedCipher).then(function (evidence) {
          var msgId = this._pushHistory(they, evidence, signedCipher.mac);
          return [evidence.body, msgId];
      }.bind(this));
    }
  };

  this._pushHistory = function(contact, evidence, mac) {
    var our = this.userProfile;
    if(our.history == undefined){
      our.history = {};
    }
    if(our.history[contact] == undefined){
      our.history[contact] = [];
    }
    our.history[contact].push({evidence: evidence, mac: mac});
    return our.history[contact].length - 1;
  };

  this.getAbuseReport = function (senderId, msgId) {
    var our = this.userProfile;
    var they = senderId.identifier;
    if (!our.history || !our.history[they]) {
        throw new Error('reportAbuse: not found ' + they + ' in history');
    }
    var history = our.history[they];
    console.log(history);
    if (!history[msgId]) {
        throw new Error('reportAbuse: not found message ID' + msgId + ' in history');
    }
    var report = {
        evidence: history[msgId].evidence,
        mac: history[msgId].mac,
    };
    return report;
  };
}


angular.module('messengerApp', [])
  .controller('MsgController', function($scope) {
    var messengerServer = new MessengerServer();
    var clients = {
        Alice: new MessengerClient(),
        Bob: new MessengerClient(),
    };
    var messenger = this;
    messenger.plaintexts = [];

    messenger.keyGen = function(sender, identifier, keyId) {
      return clients[sender].init(sender, identifier, keyId).then(function (publicId) {
          messengerServer.setPublicId(sender, publicId);
      });
    };

    //-----------------------------------------------
    // Input the name of sender and receiver
    //-----------------------------------------------
    messenger.send = function(sender, rcver) {
      var plaintext = messenger._getAndSetTextbox(sender, '');
      clients[sender].sendMessage(messengerServer.getPublicId(rcver), plaintext).
      then(function (ciphertext) {
          return messengerServer.signMessage(ciphertext);
      }).then(function (signedCipher) {
          console.log(signedCipher);
          return clients[rcver].receiveMessage(
              messengerServer.getPublicId(sender), signedCipher);
      }).then(function (result) {
        var plaintext = result[0], msgId = result[1];
        plaintext = dcodeIO.ByteBuffer.wrap(plaintext, "utf8").toString("utf8");
        console.log(plaintext);

        var plaintextAlign = (sender == 'Bob'? 'left' : 'right');
        messenger.plaintexts.push({
            text: plaintext,
            sender: sender, 
            rcver: rcver,
            align: plaintextAlign,
            abuse: false,
            id: msgId,
        });
        $scope.$apply();
      });
    };

    messenger.reportAbuse = function(sender, rcver, msgId){
      var senderId = messengerServer.getPublicId(sender);
      var report = clients[rcver].getAbuseReport(senderId, msgId);
      return messengerServer.reportAbuse('', '', report.evidence, report.mac).
      then(function () {
          console.log('reportAbuse() success');
          var index = messenger.plaintexts.findIndex(function (element) {
              return (element.id == msgId && element.rcver == rcver);
          });
          messenger.plaintexts[index].abuse = true;
          $scope.$apply();
      });
    }

    messenger.isString = function(s) {
        return angular.isString(s);
    };

    messenger._getAndSetTextbox = function(sender, rcver) {
      var plaintext;
      if(sender == 'Alice'){
        plaintext = messenger.aliceMsg;
        messenger.aliceMsg = '';
      }
      else{
        plaintext = messenger.bobMsg;
        messenger.bobMsg = '';
      }
      return plaintext;
    };

  });


/*
Copyright 2018 Google Inc. All Rights Reserved.
Use of this source code is governed by an MIT-style license that
can be found in the LICENSE file at http://angular.io/license
*/
