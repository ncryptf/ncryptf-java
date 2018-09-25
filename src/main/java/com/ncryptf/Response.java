package com.ncryptf;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.SodiumJava;
import com.goterl.lazycode.lazysodium.interfaces.Box;
import com.goterl.lazycode.lazysodium.interfaces.GenericHash;
import com.goterl.lazycode.lazysodium.interfaces.Sign;

import com.ncryptf.exceptions.DecryptionFailedException;
import com.ncryptf.exceptions.InvalidChecksumException;
import com.ncryptf.exceptions.InvalidSignatureException;
import com.ncryptf.exceptions.SignatureVerificationException;

import org.apache.commons.codec.binary.Hex;

public class Response
{
    /**
     * KeyPair for the reuqest
     */
    private Keypair keypair;

    /**
     * Secret key bytes
     */
    private byte[] secretKey;

    /**
     * Libsodium implementation
     */
    private LazySodiumJava sodium;

    /**
     * Constructor 
     * 
     * @param secretKey 32 byte secret key
     */
    public Response(byte[] secretKey)
    {
        this.sodium = new LazySodiumJava(new SodiumJava());
        this.secretKey = secretKey;
    }
    /**
     * Constructor 
     * 
     * @param secretKey 32 byte secret key
     * @param publicKey 32 byte public key
     */
    public Response(byte[] secretKey, byte[] publicKey)
    {
        this.sodium = new LazySodiumJava(new SodiumJava());
        this.keypair = new Keypair(secretKey, publicKey);
    }

    /**
     * Decrypts a v2 encrypted body
     * 
     * @param response Byte data returned by the server
     * @return Decrypted response as a String
     * @throws DecryptionFailedException
     * @throws InvalidChecksumException
     * @throws InvalidSignatureException
     */
    public String decrypt(byte[] response) throws DecryptionFailedException, InvalidChecksumException, InvalidSignatureException
    {
        if (response.length < 236) {
            throw new DecryptionFailedException();
        }
        byte[] nonce = Arrays.copyOfRange(response, 4, 28);
        return this.decrypt(response, nonce);
    }

    /**
     * Decrypts a v1 or a v2 encrypted body
     * @param response Byte data returned by the server
     * @param nonce 24 byte nonce
     * @return Decrypted response as a string
     * @throws DecryptionFailedException
     * @throws InvalidChecksumException
     * @throws InvalidSignatureException
     */
    public String decrypt(byte[] response, byte[] nonce) throws DecryptionFailedException, InvalidChecksumException, InvalidSignatureException
    {
        int version = this.getVersion(response);
        if (version == 2) {
            /**
             * Payload should be a minimum of 236 bytes
             * 4 byte header
             * 24 byte nonce
             * 32 byte public key
             * 16 byte Box.MACBYTES
             * 32 byte signature public key
             * 64 byte signature
             * 64 byte checksum
             */
            if (response.length < 236) {
                throw new DecryptionFailedException();
            }
            byte[] payload = Arrays.copyOfRange(response, 0, response.length - 64);
            byte[] checksum = Arrays.copyOfRange(response, response.length - 64, response.length);
            GenericHash.Native gh = (GenericHash.Native) this.sodium;

            byte[] calculatedChecksum = new byte[64];
            if (!gh.cryptoGenericHash(calculatedChecksum, 64, payload, payload.length, nonce, nonce.length)) {
                throw new DecryptionFailedException();
            }

            // If the checksum is invalid, throw an exception
            if (!Arrays.equals(checksum, calculatedChecksum)) {
                throw new InvalidChecksumException();
            }

            byte[] publicKey = Arrays.copyOfRange(response, 28, 60);
            byte[] signature = Arrays.copyOfRange(payload, payload.length - 64, payload.length);
            byte[] sigPubKey = Arrays.copyOfRange(payload, payload.length - 96, payload.length - 64);
            byte[] body = Arrays.copyOfRange(payload, 60, payload.length - 96);

            this.keypair = new Keypair(this.secretKey, publicKey);

            String decryptedPayload = this.decryptBody(body, nonce);

            try {
                if (!this.isSignatureValid(decryptedPayload, signature, sigPubKey)) {
                    throw new InvalidSignatureException();
                }
            } catch (SignatureVerificationException e) {
                throw new InvalidSignatureException();
            }

            return decryptedPayload;
        }

        return this.decryptBody(response, nonce);
    }
    
    /**
     * Decrypts the raw response
     * 
     * @param response  Raw byte array response from the server
     * @param nonce     24 byte nonce sent by the server
     * @return          Returns the decrypted payload as a string
     * @throws DecryptionFailedException
     */
    private String decryptBody(byte[] response, byte[] nonce) throws DecryptionFailedException
    {
        try {
            Box.Native box = (Box.Native) this.sodium;
            if (response.length < Box.MACBYTES) {
                throw new DecryptionFailedException();
            }
            byte[] message = new byte[response.length - Box.MACBYTES];

            boolean result = box.cryptoBoxOpenEasy(
                message,
                response,
                response.length,
                nonce,
                this.keypair.getPublicKey(),
                this.keypair.getSecretKey()
            );

            if (result) {
                return new String(message, "UTF-8");
            }
        } catch (UnsupportedEncodingException e) {
            throw new DecryptionFailedException();
        }

        return null;
    }

    /**
     * Returns true if the detached signature is valid
     * 
     * @param response  The decrypted response to verify
     * @param signature 64 byte signature
     * @param publicKey 32 byte public key of the signature
     * @return          `true` if the signature is valid, false otherwise
     * @throws SignatureVerificationException
     */
    public boolean isSignatureValid(String response, byte[] signature, byte[] publicKey) throws SignatureVerificationException
    {
        try {
            Sign.Native sign = (Sign.Native) this.sodium;
            byte[] message = response.getBytes("UTF-8");

            return sign.cryptoSignVerifyDetached(
                signature,
                message,
                message.length,
                publicKey
            );
        } catch (UnsupportedEncodingException e) {
            throw new SignatureVerificationException();
        }
    }

    /**
     * Returns the version from the response
     * 
     * @param response
     * @return int
     */
    private int getVersion(byte[] response) throws DecryptionFailedException
    {
        if (response.length < 16) {
            throw new DecryptionFailedException();
        }

        byte[] header = Arrays.copyOfRange(response, 0, 4);
        String hex = new String(Hex.encodeHex(header)).toUpperCase();

        if (hex.equals("DE259002")) {
            return 2;
        }

        return 1;
    }
}