package com.bravos2k5.encryption;

public interface Hmac512Service {

    String signData(String data, String secret);

    boolean verifyData(String data, String secret, String signature);

}
