package com.antonvovk;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

@RequiredArgsConstructor
public class SignatureVerificationRsaPssPoc {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    @SneakyThrows
    public void run() {
        var signatureInput = """
                "@method": POST
                "@authority": example.com
                "@path": /foo
                "content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
                "content-length": 18
                "content-type": application/json
                "@signature-params": ("@method" "@authority" "@path" "content-digest" "content-length" "content-type");created=1618884473;keyid="test-key-rsa-pss\"""";

        var signer = getSigner(signatureInput.getBytes());
        var createdSignature = Base64.getEncoder().encode(signer.sign());
        System.out.println(new String(createdSignature));

        System.out.println(getVerifier(signatureInput.getBytes()).verify(Base64.getDecoder().decode(createdSignature)));
        System.out.println(getVerifier(signatureInput.getBytes()).verify(Base64.getDecoder().decode(("HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrlFrCGUDih47vAxi4L2YRZ3XMJc1uOKk/J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxHLMCy8uqK488o+9jrptQ+xFPHK7a9sRL1IXNaagCNN3ZxJsYapFj+JXbmaI5rtAdSfSvzPuBCh+ARHBmWuNo1UzVVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzTZsL9y9TP5FsZYzHvDqbInkTNigBcE9cKOYNFCn4D/WM7F6TNuZO9EgtzepLWcjTymlHzK7aXq6Am6sfOrpIC49yXjj3ae6HRalVc/g==").getBytes())));
        System.out.println(getVerifier(signatureInput.getBytes()).verify(Base64.getDecoder().decode(("l5ORnUp57wx2m/leI6C0UAxAJIxk+L0GFGZPfJCF8nYQ1QHAgaoufa9QqdeIB6mE0MY1aqLS3vGd+BxtZ3sJYOAP+vWApYoPRW3h0FIPu0gGO192Gmm5QWgDn+RwDBuhCqdNRv7DZ9oZ7Xvkm8JvC4vIMTCLsICThh9+EwLPJaL4m3IrE4W9T/4CSi9QiYFy66ijnriTq954gjMBtPvPMM8t5HpngfgteJ2krslHQG2S5A1rYgoJU9EWrUCQcTslm9fElQHbv3zi+uNSIuGyLnWNna96NKqipT3MWPwDEGb4xkezIiyUZQadmhpVg+UGuqqzEOzjtXQvK404ZLD/FQ==").getBytes())));
    }

    // https://datatracker.ietf.org/doc/html/rfc9421#name-rsassa-pss-using-sha-512
    @SneakyThrows
    private Signature getSigner(byte[] data) {
        var signer = Signature.getInstance("SHA512withRSA/PSS");
        signer.initSign(privateKey);
        signer.update(data);
        return signer;
    }

    // https://datatracker.ietf.org/doc/html/rfc9421#name-rsassa-pss-using-sha-512
    @SneakyThrows
    private Signature getVerifier(byte[] data) {
        var verifier = Signature.getInstance("SHA512withRSA/PSS");
        verifier.initVerify(publicKey);
        verifier.update(data);
        return verifier;
    }
}
