package com.bravos2k5.encryption.impl;

import com.bravos2k5.encryption.RSAService;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
public class RSAServiceImpl implements RSAService {

    private static final String ALGORITHM = "RSA";
    private static final KeyFactory KEY_FACTORY;
    private static final KeyPairGenerator KEY_PAIR_GENERATOR;

    static {
        try {
            KEY_FACTORY = KeyFactory.getInstance(ALGORITHM);
            KEY_PAIR_GENERATOR = KeyPairGenerator.getInstance(ALGORITHM);
            KEY_PAIR_GENERATOR.initialize(2048);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String encrypt(String plainText, String publicKey) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, convertPublicKey(publicKey));
            byte[] encryptedData = cipher.doFinal(plainText.getBytes());
            return Base64.getEncoder().encodeToString(encryptedData);
        } catch (Exception e) {
            return "";
        }
    }

    @Override
    public String decrypt(String encryptedData, String privateKey) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, convertPrivateKey(privateKey));
            byte[] encryptedDataBytes = Base64.getDecoder().decode(encryptedData);
            byte[] decryptedData = cipher.doFinal(encryptedDataBytes);
            return new String(decryptedData);
        } catch (Exception e) {
            return "";
        }
    }

    @Override
    public String getSignatureData(String data, String privateKey) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(convertPrivateKey(privateKey));
            signature.update(data.getBytes());
            byte[] signDataBytes = signature.sign();
            return Base64.getEncoder().encodeToString(signDataBytes);
        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
            return "";
        }
    }

    @Override
    public boolean verifyData(String data, String signatureData, String publicKey) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            byte[] signedDataBytes = Base64.getDecoder().decode(signatureData);
            signature.initVerify(convertPublicKey(publicKey));
            signature.update(data.getBytes());
            return signature.verify(signedDataBytes);
        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
            return false;
        }
    }

    @Override
    public String generatePrivateKey() {
        KeyPair keyPair = KEY_PAIR_GENERATOR.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    @Override
    public String generatePublicKey(String privateKey) {
        try {
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKey);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) KEY_FACTORY.generatePrivate(keySpec);
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(rsaPrivateKey.getModulus(), BigInteger.valueOf(65537));
            RSAPublicKey publicKey = (RSAPublicKey) KEY_FACTORY.generatePublic(publicKeySpec);
            return Base64.getEncoder().encodeToString(publicKey.getEncoded());
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException("Invalid private key");
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        KeyPair keyPair = KEY_PAIR_GENERATOR.generateKeyPair();
        return new KeyPair(keyPair.getPublic(), keyPair.getPrivate());
    }

    private PublicKey convertPublicKey(String publicKey) {
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            return KEY_FACTORY.generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException("Invalid public key");
        }
    }

    private PrivateKey convertPrivateKey(String privateKey) {
        try {
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKey);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            return KEY_FACTORY.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException("Invalid private key");
        }
    }

}
