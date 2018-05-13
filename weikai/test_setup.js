
function initClient(identifier, keyId){
  // var identifier = "CS.6431";
  // var keyId = 6431;
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
    return ret;
  });
}


function buildSession(sender, rcver){ 
  var address = new libsignal.SignalProtocolAddress(rcver.identifier, rcver.keyId);
  var sessionBuilder = new libsignal.SessionBuilder(sender.store, address);
  return sessionBuilder.processPreKey({
      // FIXIT: use get/put
      registrationId: rcver.identifier,
      identityKey: rcver.store.store.identityKeyMay.pubKey,
      signedPreKey: {
          keyId: rcver.keyId,
          publicKey: rcver.store.store["25519KeysignedKey2018"].pubKey,
          signature: rcver.store.store["25519KeysignedKey2018"].signature,
      },
      preKey:{
          keyId: rcver.keyId,
          publicKey: rcver.store.store["25519KeypreKey2018"].pubKey,
      }
  });
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
  var address = new libsignal.SignalProtocolAddress(sender.identifier, sender.keyId);
  var sessionCipher = new libsignal.SessionCipher(rcver.store, address);
  rcver.sessionCipher = sessionCipher;
  return sessionCipher.decryptPreKeyWhisperMessage(ciphertext.body, "binary");
}

function doDecrypt(sender, rcver, ciphertext) {
  var address = new libsignal.SignalProtocolAddress(sender.identifier, sender.keyId);
  return rcver.sessionCipher.decryptWhisperMessage(ciphertext.body, "binary");
}

angular.module('messengerApp', [])
  .controller('MsgController', function() {
    var messenger = this;
    messenger.plaintexts = [];

    messenger.send = function(sender) {
      var textAlign = 'left';
      var plaintext = messenger.aliceMsg;
      if(sender == 'Bob'){
        textAlign = 'right';
        plaintext = messenger.bobMsg;
      }
      console.log(messenger.sender);
      messenger.plaintexts.push({
          text: plaintext,
          sender: sender, 
          align: textAlign});
      if(sender == 'Alice'){
        messenger.aliceMsg = '';
      }
      else{
        messenger.bobMsg = '';
      }
    };

    messenger.isString = function(s) {
        return angular.isString(s);
    };

  });


/*
Copyright 2018 Google Inc. All Rights Reserved.
Use of this source code is governed by an MIT-style license that
can be found in the LICENSE file at http://angular.io/license
*/



