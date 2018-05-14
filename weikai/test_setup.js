


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
  return sender.sessionCipher.encrypt(plaintext);
}


function newDecrypt(sender, rcver, ciphertext) {
  // var address = new libsignal.SignalProtocolAddress(sender.identifier, sender.keyId);
  // var sessionCipher = new libsignal.SessionCipher(rcver.store, address);
  // rcver.sessionCipher = sessionCipher;
  // return sessionCipher.decryptPreKeyWhisperMessage(ciphertext.body, "binary");
  return {
      header: 'H (ArrayBuffer)',
      body: 'M (ArrayBuffer)',
      commitKey: 'Kf (ArrayBuffer)',
      commitment: 'C2 (ArrayBuffer)',
  };
}

function doDecrypt(sender, rcver, ciphertext) {
  // var address = new libsignal.SignalProtocolAddress(sender.identifier, sender.keyId);
  // return rcver.sessionCipher.decryptWhisperMessage(ciphertext.body, "binary");
  return {
      header: 'H (ArrayBuffer)',
      body: 'M (ArrayBuffer)',
      commitKey: 'Kf (ArrayBuffer)',
      commitment: 'C2 (ArrayBuffer)',
  };
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
      return newEncrypt(sender, rcver, plaintext);
    });
  }
  else{
    // console.log('doEncrypt');
    return doEncrypt(sender, rcver, plaintext);
  }
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
    return newDecrypt(sender, rcver, ciphertext);
  }
  else{
    rcver.handShake[sender.name] = true;
    // console.log('doDecrypt');

    return doDecrypt(sender, rcver, ciphertext);
  }
}



//-----------------------------------------------
// Generate the secret key of the server
// Return Promise of server setting.
//-----------------------------------------------
var server = function(){
  var secretKey;
  var userList = {};

  init = function() {
    //TODO: generate random symmetric key
    secretKey = "testkey"
  }

  signMessage = function(sender, rcver, msg){
    var evidence;

    if (msg.type == 1){
      buffer = dcodeIO.ByteBuffer.wrap(msg.body, 'binary').toArrayBuffer(); 
    }
    if (msg.type == 3){
      var buffer = dcodeIO.ByteBuffer.wrap(msg.body, 'binary'); // PrekeyMsg
      var version = buffer.readUint8();
    }
    // TODO: sign on evidence (sender || rcver || C2)
    Internal.crypto.sign(key, byteArray.buffer).then(
      );
    msg.evidence = evidence;
  }

  report = function(reporter, sender, msg, keyF, evidence){
    //TODO: check if evidence is correctly signed

    //TODO: recalculate C2', compare with C2

    //TODO: if all passed, return success
  }
}
server.init();



angular.module('messengerApp', [])
  .controller('MsgController', function() {
    var globalStorage = {};
    var messenger = this;
    messenger.plaintexts = [];

    messenger.keyGen = function(sender, identifier, keyId) {
      initClient(identifier, keyId).then(function (user){
          user.name = sender;
          globalStorage[sender] = user;
          console.log(user);
      });
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
        // draw sender...
        //TODO: ask server to sign C2
        console.log(ciphertext);
        return receiveMessage(senderStorage, rcverStorage, ciphertext);
      }).then(function (plaintext) {
          return dcodeIO.ByteBuffer.wrap(plaintext, "utf8").toString("utf8");
      }).then(function (plaintext) {
        //TODO: check if the evidence is 

        //TODO: store the signed evidence for reporting in future
        console.log(plaintext);
        // draw receiver...
      });
    };
    // messenger.sendOld = function(sender, rcver) {
    //   var textAlign = 'left';
    //   var plaintext = messenger.aliceMsg;
    //   if(sender == 'Bob'){
    //     textAlign = 'right';
    //     plaintext = messenger.bobMsg;
    //   }
    //   console.log(messenger.sender);
    //   messenger.plaintexts.push({
    //       text: plaintext,
    //       sender: sender, 
    //       align: textAlign});
    //   if(sender == 'Alice'){
    //     messenger.aliceMsg = '';
    //   }
    //   else{
    //     messenger.bobMsg = '';
    //   }
    // };

    //TODO: listener to report button

    messenger.isString = function(s) {
        return angular.isString(s);
    };

  });


/*
Copyright 2018 Google Inc. All Rights Reserved.
Use of this source code is governed by an MIT-style license that
can be found in the LICENSE file at http://angular.io/license
*/



