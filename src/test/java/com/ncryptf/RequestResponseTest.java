package com.ncryptf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.util.Base64;

import com.ncryptf.exceptions.DecryptionFailedException;
import com.ncryptf.exceptions.EncryptionFailedException;
import com.ncryptf.exceptions.InvalidChecksumException;
import com.ncryptf.exceptions.InvalidSignatureException;
import com.ncryptf.exceptions.SignatureVerificationException;
import com.ncryptf.exceptions.SigningException;

import org.apache.commons.codec.binary.Hex;

import org.junit.jupiter.api.Test;

public class RequestResponseTest
{
    private byte[] clientKeyPairSecret = Base64.getDecoder().decode("bvV/vnfB43spmprI8aBK/Fd8xxSBlx7EhuxfxxTVI2o=");
    private byte[] clientKeyPairPublic = Base64.getDecoder().decode("Ojnr0KQy6GJ6x+eQa+wNwdHejZo8vY5VNyZY5NfwBjU=");
    
    private byte[] serverKeyPairSecret = Base64.getDecoder().decode("gH1+ileX1W5fMeOWue8HxdREnK04u72ybxCQgivWoZ4=");
    private byte[] serverKeyPairPublic = Base64.getDecoder().decode("YU74X2OqHujLVDH9wgEHscD5eyiLPvcugRUZG6R3BB8=");

    private byte[] signatureKeyPairSecret = Base64.getDecoder().decode("9wdUWlSW2ZQB6ImeUZ5rVqcW+mgQncN1Cr5D2YvFdvEi42NKK/654zGtxTSOcNHPEwtFAz0A4k0hwlIFopZEsQ==");
    private byte[] signatureKeyPairPublic = Base64.getDecoder().decode("IuNjSiv+ueMxrcU0jnDRzxMLRQM9AOJNIcJSBaKWRLE=");

    private byte[] nonce = Base64.getDecoder().decode("bulRnKt/BvwnwiCMBLvdRM5+yNFP38Ut");

    private byte[] expectedCipher = Base64.getDecoder().decode("1odrjBif71zRcZidfhEzSb80rXGJGB1J3upTb+TwhpxmFjXOXjwSDw45e7p/+FW4Y0/FDuLjHfGghOG0UC7j4xmX8qIVYUdbKCB/dLn34HQ0D0NIM6N9Qj83bpS5XgK1o+luonc0WxqA3tdXTcgkd2D+cSSSotJ/s+5fqN3w5xsKc7rKb1p3MpvRzyEmdNgJCFOk8EErn0bolz9LKyPEO0A2Mnkzr19bDwsgD1DGEYlo0i9KOw06RpaZRz2J+OJ+EveIlQGDdLT8Gh+nv65TOKJqCswOly0=");
    private byte[] expectedSignature = Base64.getDecoder().decode("dcvJclMxEx7pcW/jeVm0mFHGxVksY6h0/vNkZTfVf+wftofnP+yDFdrNs5TtZ+FQ0KEOm6mm9XUMXavLaU9yDg==");

    private byte[] expectedv2Cipher = Base64.getDecoder().decode("3iWQAm7pUZyrfwb8J8IgjAS73UTOfsjRT9/FLTo569CkMuhiesfnkGvsDcHR3o2aPL2OVTcmWOTX8AY11odrjBif71zRcZidfhEzSb80rXGJGB1J3upTb+TwhpxmFjXOXjwSDw45e7p/+FW4Y0/FDuLjHfGghOG0UC7j4xmX8qIVYUdbKCB/dLn34HQ0D0NIM6N9Qj83bpS5XgK1o+luonc0WxqA3tdXTcgkd2D+cSSSotJ/s+5fqN3w5xsKc7rKb1p3MpvRzyEmdNgJCFOk8EErn0bolz9LKyPEO0A2Mnkzr19bDwsgD1DGEYlo0i9KOw06RpaZRz2J+OJ+EveIlQGDdLT8Gh+nv65TOKJqCswOly0i42NKK/654zGtxTSOcNHPEwtFAz0A4k0hwlIFopZEsXXLyXJTMRMe6XFv43lZtJhRxsVZLGOodP7zZGU31X/sH7aH5z/sgxXazbOU7WfhUNChDpuppvV1DF2ry2lPcg4SwqYwa53inoY2+eCPP4Hkp/PKhSOEMFlWV+dlQirn6GGf5RQSsQ7ti/QCvi/BRIhb3ZHiPptZJZIbYwqIpvYu");

    private String payload = "{\n" +
    "    \"foo\": \"bar\",\n" +
    "    \"test\": {\n" +
    "        \"true\": false,\n" +
    "        \"zero\": 0.0,\n" +
    "        \"a\": 1,\n" +
    "        \"b\": 3.14,\n" +
    "        \"nil\": null,\n" +
    "        \"arr\": [\n" +
    "            \"a\", \"b\", \"c\", \"d\"\n" +
    "        ]\n" +
    "    }\n" +
    "}";

    @Test
    void testv2EncryptDecrypt()
    {
        try {
            Request request = new Request(
                this.clientKeyPairSecret,
                this.signatureKeyPairSecret
            );

            byte[] cipher = request.encrypt(this.payload, this.serverKeyPairPublic, 2, this.nonce);

            String eCipher = new String(Hex.encodeHex(this.expectedv2Cipher));
            String aCipher = new String(Hex.encodeHex(cipher));
            assertEquals(eCipher, aCipher);

            Response response = new Response(
                serverKeyPairSecret
            );

            String decrypted = response.decrypt(cipher);
            assertEquals(payload, decrypted);
        } catch (EncryptionFailedException | DecryptionFailedException | InvalidChecksumException | InvalidSignatureException e) {
            fail(e);
        }
    }

    @Test
    void testv2EncryptDecryptWithEmptyPayload()
    {
        try {
            Request request = new Request(
                this.clientKeyPairSecret,
                this.signatureKeyPairSecret
            );

            byte[] cipher = request.encrypt("", this.serverKeyPairPublic, 2, this.nonce);

            Response response = new Response(
                this.serverKeyPairSecret
            );

            String decrypted = response.decrypt(cipher);
            assertEquals("", decrypted);
        } catch (EncryptionFailedException | DecryptionFailedException | InvalidChecksumException | InvalidSignatureException e) {
            fail(e);
        }
    }

    @Test
    void testv2DecryptWithSmallPayload()
    {
        assertThrows(IllegalArgumentException.class, () -> {
            byte[] header = Hex.decodeHex("DE259002");
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            stream.write(header);
            stream.write(new byte[231]);

            Response response = new Response(
                serverKeyPairSecret
            );
            response.decrypt(stream.toByteArray(), this.clientKeyPairPublic);
        });
    }

    @Test
    void testv1DecryptWithSmallPayload()
    {
        assertThrows(IllegalArgumentException.class, () -> {
            byte[] cipher = new byte[15];

            Response response = new Response(
                serverKeyPairSecret
            );
            response.decrypt(cipher, this.clientKeyPairPublic);
        });
    }

    @Test
    void testv1EncryptDecrypt()
    {
        try {
            Request request = new Request(
                this.clientKeyPairSecret,
                this.signatureKeyPairSecret
            );
            byte[] cipher = request.encrypt(this.payload, this.serverKeyPairPublic, 1, this.nonce);
            byte[] signature = request.sign(this.payload);

            Response response = new Response(
                this.serverKeyPairSecret
            );

            String decrypted = response.decrypt(cipher, this.clientKeyPairPublic, this.nonce);

            String eCipher = new String(Hex.encodeHex(this.expectedCipher));
            String aCipher = new String(Hex.encodeHex(cipher));

            String eSignature = new String(Hex.encodeHex(this.expectedSignature));
            String aSignature = new String(Hex.encodeHex(signature));
            
            assertEquals(eCipher, aCipher);
            assertEquals(eSignature, aSignature);
            assertEquals(payload, decrypted);

            boolean isSignatureValid = response.isSignatureValid(
                decrypted,
                signature,
                this.signatureKeyPairPublic
            );

            assertTrue(isSignatureValid);
        } catch (IllegalArgumentException | EncryptionFailedException | DecryptionFailedException | SigningException | SignatureVerificationException | InvalidChecksumException | InvalidSignatureException e) {
            fail(e);
        }
    }
}
