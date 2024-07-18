package com.antonvovk;

import lombok.SneakyThrows;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyUtils {

    @SneakyThrows
    public static PublicKey loadPublicKeyFromFile(String resource) {
        try (var inputStream = KeyUtils.class.getClassLoader().getResourceAsStream(resource)) {
            return loadPublicKey(new String(inputStream.readAllBytes()));
        }
    }

    @SneakyThrows
    public static PrivateKey loadPrivateKeyFromFile(String resource) {
        try (var inputStream = KeyUtils.class.getClassLoader().getResourceAsStream(resource)) {
            return loadPrivateKey(new String(inputStream.readAllBytes()));
        }
    }

    @SneakyThrows
    public static PublicKey loadPublicKey(String content) {
        var key = content.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        var decodedKey = Base64.getDecoder().decode(key);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decodedKey));
    }

    @SneakyThrows
    public static PrivateKey loadPrivateKey(String content) {
        var key = content.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");
        var decodedKey = Base64.getDecoder().decode(key);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decodedKey));
    }
}
