package com.bravos2k5.encryption.impl;

import com.bravos2k5.encryption.Hmac512Service;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Service
public class Hmac512ServiceImpl implements Hmac512Service {

    @Override
    public String signData(String data, String secret) {
        try {
            byte[] keyBytes = secret.getBytes();
            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "HmacSHA512");
            Mac mac = Mac.getInstance("HmacSHA512");
            mac.init(secretKeySpec);
            byte[] hmacBytes = mac.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(hmacBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean verifyData(String data, String secret, String signature) {
        return signData(data, secret).equals(signature);
    }

}
