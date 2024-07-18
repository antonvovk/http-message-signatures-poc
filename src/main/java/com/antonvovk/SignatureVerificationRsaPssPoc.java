package com.antonvovk;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
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

        var signer = getSigner();
        signer.update(signatureInput.getBytes());
        var createdSignature = Base64.getEncoder().encode(signer.sign());
        System.out.println(new String(createdSignature));

        var verifier = getVerifier();
        verifier.update(signatureInput.getBytes());
        System.out.println(verifier.verify(Base64.getDecoder().decode(createdSignature)));
        System.out.println(verifier.verify(Base64.getDecoder().decode(("HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrlFrCGUDih47vAxi4L2" +
                "YRZ3XMJc1uOKk/J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxHLMCy8uqK488o+9jrptQ" +
                "+xFPHK7a9sRL1IXNaagCNN3ZxJsYapFj+JXbmaI5rtAdSfSvzPuBCh+ARHBmWuNo1Uz" +
                "VVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzTZsL9y9TP5FsZYzHvDqbInkTNigBc" +
                "E9cKOYNFCn4D/WM7F6TNuZO9EgtzepLWcjTymlHzK7aXq6Am6sfOrpIC49yXjj3ae6H" +
                "RalVc/g==").getBytes())));
        System.out.println(verifier.verify(Base64.getDecoder().decode(("HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrl" +
                "FrCGUDih47vAxi4L2YRZ3XMJc1uOKk/J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxH" +
                "LMCy8uqK488o+9jrptQ+xFPHK7a9sRL1IXNaagCNN3ZxJsYapFj+JXbmaI5rtAdSf" +
                "SvzPuBCh+ARHBmWuNo1UzVVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzTZsL9y" +
                "9TP5FsZYzHvDqbInkTNigBcE9cKOYNFCn4D/WM7F6TNuZO9EgtzepLWcjTymlHzK7" +
                "aXq6Am6sfOrpIC49yXjj3ae6HRalVc/g==").getBytes())));
    }

    // https://datatracker.ietf.org/doc/html/rfc9421#name-rsassa-pss-using-sha-512
    @SneakyThrows
    private Signature getSigner() {
        var signer = Signature.getInstance("RSASSA-PSS");
        signer.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1));
        signer.initSign(privateKey);
        return signer;
    }

    // https://datatracker.ietf.org/doc/html/rfc9421#name-rsassa-pss-using-sha-512
    @SneakyThrows
    private Signature getVerifier() {
        var verifier = Signature.getInstance("RSASSA-PSS");
        verifier.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1));
        verifier.initVerify(publicKey);
        return verifier;
    }
}
