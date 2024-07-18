package com.antonvovk;

import lombok.SneakyThrows;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

import static com.antonvovk.KeyUtils.loadPrivateKeyFromFile;
import static com.antonvovk.KeyUtils.loadPublicKeyFromFile;

public class Main {

    public static final Provider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

    static {
        Security.addProvider(BOUNCY_CASTLE_PROVIDER);
    }

    @SneakyThrows
    public static void main(String[] args) {
        new SignatureVerificationRsaPssPoc(
                loadPrivateKeyFromFile("test-key-rsa-pss-private.key"),
                loadPublicKeyFromFile("test-key-rsa-pss-public.key")
        ).run();
    }
}
