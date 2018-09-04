package ncryptf;

import java.io.UnsupportedEncodingException;

import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.SodiumJava;
import com.goterl.lazycode.lazysodium.interfaces.Box;
import com.goterl.lazycode.lazysodium.interfaces.Sign;
import com.goterl.lazycode.lazysodium.utils.Key;
import com.goterl.lazycode.lazysodium.utils.KeyPair;

import ncryptf.exceptions.DecryptionException;
import ncryptf.exceptions.SignatureVerificationException;

public class Response
{
    private KeyPair keyPair;
    private LazySodiumJava sodium;

    /**
     * Constructor 
     * 
     * @param secretKey 32 byte secret key
     * @param publicKey 32 byte public key
     */
    public Response(byte[] secretKey, byte[] publicKey)
    {
        this.sodium = new LazySodiumJava(new SodiumJava());
        this.keyPair = new KeyPair(Key.fromBytes(publicKey), Key.fromBytes(secretKey));
    }

    /**
     * Decrypts the raw response
     * 
     * @param response  Raw byte array response from the server
     * @param nonce     24 byte nonce sent by the server
     * @return          Returns the decrypted payload as a string
     * @throws DecryptionException
     */
    public String decrypt(byte[] response, byte[] nonce) throws DecryptionException
    {
        try {
            Box.Native box = (Box.Native) this.sodium;
            byte[] message = new byte[response.length - Box.MACBYTES];

            boolean result = box.cryptoBoxOpenEasy(
                message,
                response,
                response.length,
                nonce,
                this.keyPair.getPublicKey().getAsBytes(),
                this.keyPair.getSecretKey().getAsBytes()
            );

            if (result) {
                return new String(message, "UTF-8");
            }
        } catch (UnsupportedEncodingException e) {
            throw new DecryptionException();
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
}