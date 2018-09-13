package ncryptf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import javax.xml.bind.DatatypeConverter;

import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.SodiumJava;
import com.goterl.lazycode.lazysodium.interfaces.Box;
import com.goterl.lazycode.lazysodium.interfaces.GenericHash;
import com.goterl.lazycode.lazysodium.interfaces.Sign;

import ncryptf.exceptions.EncryptionFailedException;
import ncryptf.exceptions.SigningException;

public class Request
{
    /**
     * KeyPair for the reuqest
     */
    private Keypair keypair;

    /**
     * Libsodium implementation
     */
    private LazySodiumJava sodium;

    /**
     * 24 byte nonce used for the request
     */
    private byte[] nonce;

    /**
     * Constructor 
     * 
     * @param secretKey 32 byte secret key
     * @param publicKey 32 byte public key
     */
    public Request(byte[] secretKey, byte[] publicKey)
    {
        this.sodium = new LazySodiumJava(new SodiumJava());
        this.keypair = new Keypair(
            secretKey,
            publicKey
        );
    }

    /**
     * Encrypts the payload
     * 
     * @param data          String payload to encrypt
     * @param signatureKey  32 byte signing key
     * @return              Byte array containing the encrypted data
     * @throws EncryptionFailedException
     */
    public byte[] encrypt(String data, byte[] signatureKey) throws EncryptionFailedException
    {
        byte[] nonce = this.sodium.randomBytesBuf(Box.NONCEBYTES);
        return encrypt(data, signatureKey, 2, nonce);
    }

    /**
     * Encrypts the payload with a specified version, and a generated nonce
     * 
     * @param data          String payload to encrypt
     * @param signatureKey  32 byte signing key
     * @param version       Version to generate
     * @return              Byte array containing the encrypted data
     * @throws EncryptionFailedException
     */
    public byte[] encrypt(String data, byte[] signatureKey, int version) throws EncryptionFailedException
    {
        byte[] nonce = this.sodium.randomBytesBuf(Box.NONCEBYTES);
        return encrypt(data, signatureKey, version, nonce);
    }

    /**
     * Encrypts the payload with a specified version and optional nonce
     * 
     * @param data          String payload to encrypt
     * @param signatureKey  32 byte signing key
     * @param version       Version to generate
     * @param nonce         24 byte
     * @return              Byte array containing the encrypted data
     * @throws EncryptionFailedException
     */
    public byte[] encrypt(String data, byte[] signatureKey, int version, byte[] nonce) throws EncryptionFailedException
    {
        if (version == 2) {
            byte[] header = DatatypeConverter.parseHexBinary("DE259002");
            byte[] body = this.encryptBody(data, nonce);
            byte[] publicKey = new byte[32];
            if (this.sodium.getSodium().crypto_scalarmult_base(publicKey, this.keypair.getSecretKey()) != 0) {
                throw new EncryptionFailedException();
            }

            byte[] sigPubKey = new byte[32];
            if (this.sodium.getSodium().crypto_sign_ed25519_sk_to_pk(sigPubKey, signatureKey) != 0) {
                throw new EncryptionFailedException();
            }

            try {
                byte[] signature = this.sign(data, signatureKey);
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
            } catch (SigningException | IOException e) {
                throw new EncryptionFailedException();
            }
        }

        return encryptBody(data, nonce);
    }

    /**
     * Encrypts the payload
     * 
     * @param data  String payload to encrypt
     * @param nonce 24 byte nonce
     * @return      Byte array containing the encrypted data
     * @throws EncryptionFailedException
     */
    private byte[] encryptBody(String data, byte[] nonce) throws EncryptionFailedException
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
                this.keypair.getPublicKey(),
                this.keypair.getSecretKey()
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
     * @param secretKey     Signing secret key
     * @return              64 byte signature
     * @throws SigningException
     */
    public byte[] sign(String data, byte[] secretKey) throws SigningException
    {
        try {
            byte[] message = data.getBytes("UTF-8");
            byte[] signature = new byte[Sign.BYTES];
            Sign.Native sign = (Sign.Native) this.sodium;

            boolean result = sign.cryptoSignDetached(
                signature,
                null,
                message,
                (long)message.length,
                secretKey
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