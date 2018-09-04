package ncryptf;

import java.io.UnsupportedEncodingException;

import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.SodiumJava;
import com.goterl.lazycode.lazysodium.interfaces.Box;
import com.goterl.lazycode.lazysodium.interfaces.Sign;
import com.goterl.lazycode.lazysodium.utils.Key;
import com.goterl.lazycode.lazysodium.utils.KeyPair;

import ncryptf.exceptions.EncryptionException;
import ncryptf.exceptions.SigningException;

public class Request
{
    private KeyPair keyPair;
    private byte[] nonce;
    private LazySodiumJava sodium;

    /**
     * Constructor 
     * 
     * @param secretKey 32 byte secret key
     * @param publicKey 32 byte public key
     */
    public Request(byte[] secretKey, byte[] publicKey)
    {
        this.sodium = new LazySodiumJava(new SodiumJava());
        this.keyPair = new KeyPair(Key.fromBytes(publicKey), Key.fromBytes(secretKey));
    }

    /**
     * Encrypts the payload
     * 
     * @param data  String payload to encrypt
     * @return      Byte array containing the encrypted data
     * @throws EncryptionException
     */
    public byte[] encrypt(String data) throws EncryptionException
    {
        byte[] nonce = this.sodium.randomBytesBuf(Box.NONCEBYTES);
        return encrypt(data, nonce);
    }

    /**
     * Encrypts the payload
     * 
     * @param data  String payload to encrypt
     * @param nonce 24 byte nonce
     * @return      Byte array containing the encrypted data
     * @throws EncryptionException
     */
    public byte[] encrypt(String data, byte[] nonce) throws EncryptionException
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
                this.keyPair.getPublicKey().getAsBytes(),
                this.keyPair.getSecretKey().getAsBytes()
            );
            
            if (result) {
                return cipher;
            }
        } catch (UnsupportedEncodingException e) {
            throw new EncryptionException();
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