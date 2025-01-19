package com.bravos2k5.encryption;

import java.security.KeyPair;

public interface RSAService {

    String encrypt(String plainText, String publicKey);

    String decrypt(String cipherText, String privateKey);

    String getSignatureData(String data, String privateKey);

    boolean verifyData(String data, String signature, String publicKey);

    String generatePrivateKey();

    String generatePublicKey(String privateKey);

    KeyPair generateKeyPair();

}
