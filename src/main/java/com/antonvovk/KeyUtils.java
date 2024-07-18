package com.antonvovk;

import lombok.SneakyThrows;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.openssl.PEMParser;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.reflect.Field;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static com.antonvovk.Main.BOUNCY_CASTLE_PROVIDER;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_RSASSA_PSS;

public class KeyUtils {

    @SneakyThrows
    public static PublicKey loadPublicKeyFromFile(String resource) {
        try (var inputStream = KeyUtils.class.getClassLoader().getResourceAsStream(resource);
             var reader = new BufferedReader(new InputStreamReader(inputStream))
        ) {
            return loadPublicKey(reader);
        }
    }

    @SneakyThrows
    public static PrivateKey loadPrivateKeyFromFile(String resource) {
        try (var inputStream = KeyUtils.class.getClassLoader().getResourceAsStream(resource);
             var reader = new BufferedReader(new InputStreamReader(inputStream))
        ) {
            return loadPrivateKey(reader);
        }
    }

    @SneakyThrows
    private static PublicKey loadPublicKey(Reader reader) {
        var parser = new PEMParser(reader);
        var keyInfo = (SubjectPublicKeyInfo) parser.readObject();
        var keyFactory = KeyFactory.getInstance("RSASSA-PSS", BOUNCY_CASTLE_PROVIDER);
        var key = keyFactory.generatePublic(new X509EncodedKeySpec(keyInfo.getEncoded(), "RSASSA-PSS"));
        var algorithmIdentifierField = BCRSAPublicKey.class.getDeclaredField("algorithmIdentifier");
        doBcHack(algorithmIdentifierField, key);
        return key;
    }

    @SneakyThrows
    private static PrivateKey loadPrivateKey(Reader reader) {
        var parser = new PEMParser(reader);
        var keyInfo = (PrivateKeyInfo) parser.readObject();
        var keyFactory = KeyFactory.getInstance("RSASSA-PSS", BOUNCY_CASTLE_PROVIDER);
        var key = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyInfo.getEncoded(), "RSASSA-PSS"));
        var algorithmIdentifierField = BCRSAPrivateKey.class.getDeclaredField("algorithmIdentifier");
        doBcHack(algorithmIdentifierField, key);
        return key;
    }

    // https://github.com/bcgit/bc-java/issues/1474
    @SneakyThrows
    private static void doBcHack(Field field, Key key) {
        field.setAccessible(true);
        field.set(key, new AlgorithmIdentifier(id_RSASSA_PSS));

        var algorithmIdentifier = (AlgorithmIdentifier) field.get(key);
        assert "RSASSA-PSS".equals(key.getAlgorithm());
        assert "1.2.840.113549.1.1.10".equals(algorithmIdentifier.getAlgorithm().toString());
    }
}
