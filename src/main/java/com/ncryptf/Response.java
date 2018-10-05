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
     * @throws IllegalArgumentException If the secret key length is invalid
     */
    public Response(byte[] secretKey)
    {
        this.sodium = new LazySodiumJava(new SodiumJava());
        if (secretKey.length != Box.SECRETKEYBYTES) {
            throw new IllegalArgumentException(String.format("Secret key should be %d bytes", Box.SECRETKEYBYTES));
        }

        this.secretKey = secretKey;
    }

    /**
     * Decrypts a v2 encrypted body
     * 
     * @param response      Byte data returned by the server
     * @return              Decrypted response as a String
     * @throws DecryptionFailedException If the message could not be decrypted
     * @throws InvalidChecksumException If the checksum generated from the message doesn't match the checksum associated with the message
     * @throws InvalidSignatureException If the signature check fails
     * @throws IllegalArgumentException If the response length is too short
     */
    public String decrypt(byte[] response) throws IllegalArgumentException, DecryptionFailedException, InvalidChecksumException, InvalidSignatureException
    {
        if (response.length < 236) {
            throw new IllegalArgumentException();
        }

        byte[] nonce = Arrays.copyOfRange(response, 4, 28);
        return this.decrypt(response, null, nonce);
    }

    /**
     * Decrypts a v2 encrypted body
     * 
     * @param response      Byte data returned by the server
     * @param publicKey     32 byte public key
     * @return              Decrypted response as a String
     * @throws DecryptionFailedException If the message could not be decrypted
     * @throws InvalidChecksumException If the checksum generated from the message doesn't match the checksum associated with the message
     * @throws InvalidSignatureException If the signature check fails
     * @throws IllegalArgumentException If the response length is too short
     */
    public String decrypt(byte[] response, byte[] publicKey) throws IllegalArgumentException, DecryptionFailedException, InvalidChecksumException, InvalidSignatureException
    {
        if (response.length < 236) {
            throw new IllegalArgumentException();
        }

        byte[] nonce = Arrays.copyOfRange(response, 4, 28);
        return this.decrypt(response, publicKey, nonce);
    }

    /**
     * Decrypts a v1 or a v2 encrypted body
     * @param response      Byte data returned by the server
     * @param publicKey     32 byte public key
     * @param nonce         24 byte nonce
     * @return              Decrypted response as a string
     * @throws DecryptionFailedException If the message could not be decrypted
     * @throws InvalidChecksumException If the checksum generated from the message doesn't match the checksum associated with the message
     * @throws InvalidSignatureException If the signature check fails
     * @throws IllegalArgumentException If the response length is too short
     */
    public String decrypt(byte[] response, byte[] publicKey, byte[] nonce) throws IllegalArgumentException, DecryptionFailedException, InvalidChecksumException, InvalidSignatureException
    {
        if (nonce.length != Box.NONCEBYTES) {
            throw new IllegalArgumentException(String.format("Nonce should be %d bytes.", Box.NONCEBYTES));
        }

        int version = getVersion(response);
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
                throw new IllegalArgumentException();
            }

            byte[] payload = Arrays.copyOfRange(response, 0, response.length - 64);
            byte[] checksum = Arrays.copyOfRange(response, response.length - 64, response.length);
            GenericHash.Native gh = (GenericHash.Native) this.sodium;

            byte[] calculatedChecksum = new byte[64];
            if (!gh.cryptoGenericHash(calculatedChecksum, 64, payload, payload.length, nonce, nonce.length)) {
                throw new DecryptionFailedException();
            }

            // If the checksum is invalid, throw an exception
            if (this.sodium.getSodium().sodium_memcmp(checksum, calculatedChecksum, 64) != 0) {
                throw new InvalidChecksumException();
            }

            publicKey = Arrays.copyOfRange(response, 28, 60);
            byte[] signature = Arrays.copyOfRange(payload, payload.length - 64, payload.length);
            byte[] sigPubKey = Arrays.copyOfRange(payload, payload.length - 96, payload.length - 64);
            byte[] body = Arrays.copyOfRange(payload, 60, payload.length - 96);

            String decryptedPayload = this.decryptBody(body, publicKey, nonce);

            try {
                if (!this.isSignatureValid(decryptedPayload, signature, sigPubKey)) {
                    throw new InvalidSignatureException();
                }
            } catch (SignatureVerificationException e) {
                throw new InvalidSignatureException();
            }

            return decryptedPayload;
        }

        if (publicKey.length != Box.PUBLICKEYBYTES) {
            throw new IllegalArgumentException(String.format("Public key should be %d bytes", Box.PUBLICKEYBYTES));
        }

        return this.decryptBody(response, publicKey, nonce);
    }
    
    /**
     * Decrypts the raw response
     * 
     * @param response  Raw byte array response from the server
     * @param publicKey 32 byte public key
     * @param nonce     24 byte nonce sent by the server
     * @return          Returns the decrypted payload as a string
     * @throws DecryptionFailedException If the message could not be decrypted
     */
    private String decryptBody(byte[] response, byte[] publicKey, byte[] nonce) throws IllegalArgumentException, DecryptionFailedException
    {
        if (publicKey.length != Box.PUBLICKEYBYTES) {
            throw new IllegalArgumentException(String.format("Public key should be %d bytes.", Box.PUBLICKEYBYTES));
        }

        if (nonce.length < Box.NONCEBYTES) {
            throw new IllegalArgumentException(String.format("Nonce should be %d bytes.", Box.NONCEBYTES));
        }

        if (response.length < Box.MACBYTES) {
            throw new IllegalArgumentException(String.format("Message should be at minimum %d bytes.", Box.MACBYTES));
        }

        try {
            Box.Native box = (Box.Native) this.sodium;

            byte[] message = new byte[response.length - Box.MACBYTES];

            boolean result = box.cryptoBoxOpenEasy(
                message,
                response,
                response.length,
                nonce,
                publicKey,
                this.secretKey
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
     * @throws SignatureVerificationException If the detached signature could not be generated
     */
    public boolean isSignatureValid(String response, byte[] signature, byte[] publicKey) throws SignatureVerificationException, IllegalArgumentException
    {
        if (signature.length != 64) {
            throw new IllegalArgumentException(String.format("Signature should be %d bytes.", 64));
        }

        if (publicKey.length != Sign.PUBLICKEYBYTES) {
            throw new IllegalArgumentException(String.format("Public key should be %d bytes.", Sign.PUBLICKEYBYTES));
        }

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
     * Extracts the public key from a v2 response
     * @param response  Response bytes
     * @return          32 byte public key
     * @throws IllegalArgumentException If the response length is too short, or a version 1 message was passed
     */
    public static byte[] getPublicKeyFromResponse(byte[] response) throws IllegalArgumentException
    {
        int version = getVersion(response);
        if (version == 2) {
            if (response.length < 236) {
                throw new IllegalArgumentException();
            }

            return Arrays.copyOfRange(response, 28, 60);
        }

        throw new IllegalArgumentException("The response provided is not suitable for public key extraction");
    }

    /**
     * Returns the version from the response
     * 
     * @param response  Response bytes
     * @return int      The version
     * @throws IllegalArgumentException If the response length is too short.
     */
    public static int getVersion(byte[] response) throws IllegalArgumentException
    {
        if (response.length < Box.MACBYTES) {
            throw new IllegalArgumentException();
        }

        byte[] header = Arrays.copyOfRange(response, 0, 4);
        String hex = new String(Hex.encodeHex(header)).toUpperCase();

        if (hex.equals("DE259002")) {
            return 2;
        }

        return 1;
    }
}