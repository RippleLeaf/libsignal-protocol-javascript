


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


function buildSession(sender, rcver){ 
  var address = new libsignal.SignalProtocolAddress(rcver.identifier, rcver.keyId);
  var sessionBuilder = new libsignal.SessionBuilder(sender.store, address);
  return sessionBuilder.processPreKey(rcver.publicId);
}


function newEncrypt(sender, rcver, plaintext) {
  var address = new libsignal.SignalProtocolAddress(rcver.identifier, rcver.keyId);
  var sessionCipher = new libsignal.SessionCipher(sender.store, address);
  sender.sessionCipher = sessionCipher;
  return sessionCipher.encrypt(plaintext);
}

function doEncrypt(sender, rcver, plaintext) {
  var address = new libsignal.SignalProtocolAddress(rcver.identifier, rcver.keyId);
  var test = sender.sessionCipher.encrypt(plaintext);
  console.log(test);
  return test;
  // return sender.sessionCipher.encrypt(plaintext);
}


function newDecrypt(sender, rcver, ciphertext) {
  var address = new libsignal.SignalProtocolAddress(sender.identifier, sender.keyId);
  var sessionCipher = new libsignal.SessionCipher(rcver.store, address);
  rcver.sessionCipher = sessionCipher;
  return sessionCipher.decryptPreKeyWhisperMessage(ciphertext.body, "binary").
    then(function (ret) {
        console.log(ret);
        return ret;
    });
  // return {
  //     header: 'H (ArrayBuffer)',
  //     body: 'M (ArrayBuffer)',
  //     commitKey: 'Kf (ArrayBuffer)',
  //     commitment: 'C2 (ArrayBuffer)',
  // };
}

function doDecrypt(sender, rcver, ciphertext) {
  var address = new libsignal.SignalProtocolAddress(sender.identifier, sender.keyId);
  return rcver.sessionCipher.decryptWhisperMessage(ciphertext.body, "binary").
    then(function (ret) {
        console.log(ret);
        return ret;
    });
  // return {
  //     header: 'H (ArrayBuffer)',
  //     body: 'M (ArrayBuffer)',
  //     commitKey: 'Kf (ArrayBuffer)',
  //     commitment: 'C2 (ArrayBuffer)',
  // };
}

//-----------------------------------------------
// Send encrypted message. Build a new session if not exist.
// Return Promise of a ciphertext.
//-----------------------------------------------
function sendMessage(sender, rcver, plaintext) {
  if(sender.handShake == undefined){
    sender.handShake = [];
  }
  // if the sender hasn't shaked hands with the rcv
  // build a new session

  if(sender.handShake[rcver.name] == undefined ||
      sender.handShake[rcver.name] == false){
    sender.handShake[rcver.name] = false;
    return buildSession(sender, rcver).then(function onsuccess() {
      // console.log('newEncrypt');
      var beginTime = new Date().getTime();
      var enc = newEncrypt(sender, rcver, plaintext);
      var endTime = new Date().getTime();
      console.log("run time of encryption: " + (endTime - beginTime));
      var ret = [endTime - beginTime, enc]
      return Promise.all(ret);
      // return newEncrypt(sender, rcver, plaintext);
    });
  }
  else{
    var beginTime = new Date().getTime();
    var enc = doEncrypt(sender, rcver, plaintext);
    var endTime = new Date().getTime();
    console.log("run time of encryption: " + (endTime - beginTime));
    // return {time: endTime - beginTime, cipherPromise: enc};
    var ret = [endTime - beginTime, enc]
      return Promise.all(ret);
  }
}

function _pushHistory(useProfile, contact, evidence, mac) {
  if(useProfile.history == undefined){
    useProfile.history = {};
  }
  if(useProfile.history[contact] == undefined){
    useProfile.history[contact] = [];
  }
  useProfile.history[contact].push({evidence: evidence, mac: mac});
}


//-----------------------------------------------
// Receive encrypted message. Build a new session if not exist.
// Return Promise of a plaintext.
//-----------------------------------------------
function receiveMessage(sender, rcver, ciphertext) {
  if(rcver.handShake == undefined){
    rcver.handShake = [];
  }

  if(rcver.handShake[sender.name] == undefined){
    // console.log('newDecrypt');
    rcver.handShake[sender.name] = true;

    var beginTime = new Date().getTime();
    var dec = newDecrypt(sender, rcver, ciphertext);
    var endTime = new Date().getTime();
    console.log("run time of decryption: " + (endTime - beginTime));
    var ret = [endTime - beginTime, dec]
    return Promise.all(ret);
    // return newDecrypt(sender, rcver, ciphertext).then(function (evidence) {
    //     _pushHistory(rcver, sender.name, evidence, ciphertext.mac);
    //     return evidence.body;
    // });
  }
  else{
    rcver.handShake[sender.name] = true;
    // console.log('doDecrypt');

    var beginTime = new Date().getTime();
    var dec = doDecrypt(sender, rcver, ciphertext);
    var endTime = new Date().getTime();
    console.log("run time of decryption: " + (endTime - beginTime));
    var ret = [endTime - beginTime, dec]
    return Promise.all(ret);
    // return doDecrypt(sender, rcver, ciphertext).then(function (evidence) {
    //     _pushHistory(rcver, sender.name, evidence, ciphertext.mac);
    //     return evidence.body;
    // });
  }
}



//-----------------------------------------------
// Generate the secret key of the server
// Return Promise of server setting.
//-----------------------------------------------
function MessengerServer() {
  this.secretKey = Uint8Array.from(
          [192,106,86,38,22,204,187,56,111,79,114,168,231,35,161,164,
          183,157,252,75,64,170,31,171,79,231,209,78,242,130,15,51]);
  this.userList = {};
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


var testCount = 0;

angular.module('messengerApp', [])
  .controller('MsgController', function() {
    var globalStorage = {};
    var messengerServer = new MessengerServer();
    var messenger = this;
    messenger.plaintexts = [];
    messenger.encryptionTime = 0;
    messenger.signTime = 0;
    messenger.decryptionTime = 0;

    messenger.keyGen = function(sender, identifier, keyId) {
      initClient(identifier, keyId).then(function (user){
          user.name = sender;
          globalStorage[sender] = user;
          console.log(user);
      });
    };

    messenger.genTestMessage = function(length){
      var filler = "0";
      var plaintext = "";
      for (var i = 0; i < length; i++) {
        plaintext += filler;
      }
      return plaintext;
    };

    messenger.testPerformance = function(){
      var plaintext = this.genTestMessage(messenger.msgLength);
      var sender, recvr;
      if ((testCount & 1) === 0){
        sender = 'Alice';
        recvr = 'Bob';
      }
      else {sender = 'Bob'; recvr = 'Alice';}
      testCount += 1;
      console.log("sender: " + sender + " counter: " + testCount);

      senderStorage = globalStorage[sender];
      rcverStorage = globalStorage[recvr];
      sendMessage(senderStorage, rcverStorage, plaintext)
      .then(function (package) {
        console.log(package[0]);
        messenger.encryptionTime = package[0];
        return package[1];
      }).then(function (ciphertext) {
        return receiveMessage(senderStorage, rcverStorage, ciphertext);
      }).then(function (package) {
        console.log(package);
        messenger.decryptionTime = package[0];
        return package[1];
      }).then(function (plaintext) {
        console.log(plaintext);
        return dcodeIO.ByteBuffer.wrap(plaintext, "utf8").toString("utf8");
      })
    };

    //-----------------------------------------------
    // Input the name of sender and receiver
    //-----------------------------------------------
    messenger.send = function(sender, rcver) {
      // var textAlign = 'left';
      var plaintext = messenger.aliceMsg;
      if(sender == 'Bob'){
        // textAlign = 'right';
        plaintext = messenger.bobMsg;
      }
      senderStorage = globalStorage[sender];
      rcverStorage = globalStorage[rcver];
      sendMessage(senderStorage, rcverStorage, plaintext)
      .then(function (ciphertext) {
        var beginTime = new Date.getIme();
        var sig = messengerServer.signMessage(ciphertext);
        var endTime = new Date.getIme();
        messenger.signTime = endTime - beginTime;
        return sig;
      }).then(function (signedCipher) {
        console.log(signedCipher);
        return receiveMessage(senderStorage, rcverStorage, signedCipher);
      }).then(function (plaintext) {
        return dcodeIO.ByteBuffer.wrap(plaintext, "utf8").toString("utf8");
      }).then(function (plaintext) {
        //TODO: check if the evidence is 

        //TODO: store the signed evidence for reporting in future
        var plaintextAlign = sender == 'Bob'? 'left' : 'right';
        messenger.plaintexts.push({
          text: plaintext,
          sender: sender, 
          rcver: rcver,
          align: plaintextAlign
        });
        console.log(plaintext);
        // draw receiver...
      }).then(function () {
        // Report last message
        var history = rcverStorage.history[sender];
        console.log(rcverStorage);
        var evidence = history[history.length-1].evidence;
        var mac = history[history.length-1].mac;
        return messengerServer.reportAbuse(sender, rcver, evidence, mac).then(function (argument) {
            console.log('reportAbuse() success');
        });
      });
    };

    messenger.reportAbuse = function(sender, rcver, index){
      console.log("report!!!")
    }

    messenger.isString = function(s) {
        return angular.isString(s);
    };

  });


/*
Copyright 2018 Google Inc. All Rights Reserved.
Use of this source code is governed by an MIT-style license that
can be found in the LICENSE file at http://angular.io/license
*/
