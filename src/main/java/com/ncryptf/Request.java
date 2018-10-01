package com.ncryptf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.SodiumJava;
import com.goterl.lazycode.lazysodium.interfaces.Box;
import com.goterl.lazycode.lazysodium.interfaces.GenericHash;
import com.goterl.lazycode.lazysodium.interfaces.Sign;
import com.ncryptf.exceptions.EncryptionFailedException;
import com.ncryptf.exceptions.SigningException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

final public class Request
{
    /**
     * Libsodium implementation
     */
    private LazySodiumJava sodium;

    /**
     * 32 byte secret key
     */
    private byte[] secretKey;


    /**
     * 64 byte signature secret key
     */
    private byte[] signatureSecretKey;

    /**
     * 24 byte nonce used for the request
     */
    private byte[] nonce;

    /**
     * Constructor 
     * 
     * @param secretKey             32 byte secret key
     * @param signatureSecretKey    64 byte signature secret key
     * @throws IllegalArgumentException If the secret key or signatureSecretKey byte lengths are invalid
     */
    public Request(byte[] secretKey, byte[] signatureSecretKey)
    {
        this.sodium = new LazySodiumJava(new SodiumJava());
        if (secretKey.length != Box.SECRETKEYBYTES) {
            throw new IllegalArgumentException(String.format("Secret key should be %d bytes", Box.SECRETKEYBYTES));
        }

        this.secretKey = secretKey;

        if (signatureSecretKey.length != Sign.SECRETKEYBYTES) {
            throw new IllegalArgumentException(String.format("Secret key should be %d bytes", Sign.SECRETKEYBYTES));
        }

        this.signatureSecretKey = signatureSecretKey;
    }

    /**
     * Encrypts the payload
     * 
     * @param data              String payload to encrypt
     * @param remotePublicKey   32 byte public key
     * @return                  Byte array containing the encrypted data
     * @throws EncryptionFailedException If the message cannot be encrypted
     */
    public byte[] encrypt(String data, byte[] remotePublicKey) throws EncryptionFailedException
    {
        byte[] nonce = this.sodium.randomBytesBuf(Box.NONCEBYTES);
        return encrypt(data, remotePublicKey, 2, nonce);
    }

    /**
     * Encrypts the payload with a specified version, and a generated nonce
     * 
     * @param data              String payload to encrypt
     * @param remotePublicKey   32 byte public key
     * @param version           Version to generate
     * @return                  Byte array containing the encrypted data
     * @throws EncryptionFailedException If the message cannot be encrypted
     */
    public byte[] encrypt(String data, byte[] remotePublicKey, int version) throws EncryptionFailedException
    {
        byte[] nonce = this.sodium.randomBytesBuf(Box.NONCEBYTES);
        return this.encrypt(data, remotePublicKey, version, nonce);
    }

    /**
     * Encrypts the payload with a specified version and optional nonce
     * 
     * @param data              String payload to encrypt
     * @param remotePublicKey   32 byte signing key
     * @param version           Version to generate
     * @param nonce             24 byte
     * @return                  Byte array containing the encrypted data
     * @throws EncryptionFailedException If the message cannot be encrypted
     */
    public byte[] encrypt(String data, byte[] remotePublicKey, int version, byte[] nonce) throws EncryptionFailedException
    {
        if (version == 2) {
            try {
                byte[] header = Hex.decodeHex("DE259002");
                byte[] body = this.encryptBody(data, remotePublicKey, nonce);
    
                if (body == null) {
                    throw new EncryptionFailedException();
                }
    
                byte[] publicKey = new byte[32];
                if (this.sodium.getSodium().crypto_scalarmult_base(publicKey, this.secretKey) != 0) {
                    throw new EncryptionFailedException();
                }
    
                byte[] sigPubKey = new byte[32];
                if (this.sodium.getSodium().crypto_sign_ed25519_sk_to_pk(sigPubKey, this.signatureSecretKey) != 0) {
                    throw new EncryptionFailedException();
                }

                byte[] signature = this.sign(data);
                if (signature == null) {
                    throw new EncryptionFailedException();
                }
                
                ByteArrayOutputStream stream = new ByteArrayOutputStream();
                stream.write(header);
                stream.write(nonce);
                stream.write(publicKey);
                stream.write(body);
                stream.write(sigPubKey);
                stream.write(signature);

                byte[] payload = stream.toByteArray();

                GenericHash.Native gh = (GenericHash.Native) this.sodium;

                byte[] checksum = new byte[64];
                if (!gh.cryptoGenericHash(checksum, 64, payload, payload.length, nonce, nonce.length)) {
                    throw new EncryptionFailedException();
                }

                stream.write(checksum);
                return stream.toByteArray();
            } catch (SigningException | IOException | DecoderException e) {
                throw new EncryptionFailedException();
            }
        }

        return this.encryptBody(data, remotePublicKey, nonce);
    }

    /**
     * Encrypts the payload
     * 
     * @param data      String payload to encrypt
     * @param publicKey 32 byte public key
     * @param nonce     24 byte nonce
     * @return          Byte array containing the encrypted data
     * @throws EncryptionFailedException If the message cannot be encrypted
     */
    private byte[] encryptBody(String data, byte[] publicKey, byte[] nonce) throws EncryptionFailedException
    {
        try {
            Box.Native box = (Box.Native) this.sodium;
            byte[] message = data.getBytes("UTF-8");
            byte[] cipher = new byte[Box.MACBYTES + message.length];

            boolean result = box.cryptoBoxEasy(
                cipher,
                message,
                message.length,
                nonce,
                publicKey,
                this.secretKey
            );
            
            if (result) {
                return cipher;
            }
        } catch (UnsupportedEncodingException e) {
            throw new EncryptionFailedException();
        }

        return null;
    }

    /**
     * Signs the payload
     * @param data          String payload to sign
     * @return              64 byte signature
     * @throws SigningException If the data cannot be signed
     */
    public byte[] sign(String data) throws SigningException
    {
        try {
            byte[] message = data.getBytes("UTF-8");
            byte[] signature = new byte[Sign.BYTES];
            Sign.Native sign = (Sign.Native) sodium;

            boolean result = sign.cryptoSignDetached(
                signature,
                null,
                message,
                (long)message.length,
                this.signatureSecretKey
            );

            if (result) {
                return signature;
            }
        } catch (UnsupportedEncodingException e) {
            throw new SigningException();
        }

        return null;
    }

    /**
     * @return 24 byte nonce used for encryption
     */
    public byte[] getNonce()
    {
        return this.nonce;
    }
}