package com.bravos2k5.bravosencryption.service.impl;

import com.bravos2k5.bravosencryption.service.AESEncryptionService;
import org.springframework.stereotype.Service;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class AESEncryptionServiceImpl implements AESEncryptionService {

    private static final int GCM_TAG_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final String ALGORITHM = "AES/GCM/NoPadding";

    @Override
    public String encrypt(String plainText, String secretKey) {
        try {
            byte[] iv = generateIV();
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey(secretKey), spec);
            byte[] cipherText = cipher.doFinal(plainText.getBytes());
            ByteBuffer byteBuffer = ByteBuffer.allocate(IV_LENGTH + cipherText.length);
            byteBuffer.put(iv);
            byteBuffer.put(cipherText);
            return Base64.getEncoder().encodeToString(byteBuffer.array());
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException
                 | BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException e) {
            return "";
        }
    }

    @Override
    public String decrypt(String encryptedText, String secretKey) {
        try {
            ByteBuffer byteBuffer = ByteBuffer.wrap(Base64.getDecoder().decode(encryptedText));
            byte[] iv = new byte[IV_LENGTH];
            byteBuffer.get(iv);
            byte[] cypherText = new byte[byteBuffer.remaining()];
            byteBuffer.get(cypherText);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, convertSecretKey(secretKey), spec);
            byte[] plainText = cipher.doFinal(cypherText);
            return new String(plainText);
        } catch (BadPaddingException | IllegalBlockSizeException |
                 InvalidAlgorithmParameterException | InvalidKeyException
                | NoSuchPaddingException | NoSuchAlgorithmException e) {
            return "";
        }
    }

    @Override
    public String generateSecretKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            return Base64.getEncoder().encodeToString(keyGenerator.generateKey().getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private SecretKey convertSecretKey(String secretKey) {
        byte[] decodedKey = Base64.getDecoder().decode(secretKey);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    private byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

}
