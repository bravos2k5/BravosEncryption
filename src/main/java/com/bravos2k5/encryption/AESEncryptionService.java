package com.bravos2k5.encryption;

public interface AESEncryptionService {

    String encrypt(String plainText, String  secretKey);

    String decrypt(String cipherText, String secretKey);

    String generateSecretKey();

}
