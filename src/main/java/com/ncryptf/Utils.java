package com.ncryptf;

import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.SodiumJava;
import com.goterl.lazycode.lazysodium.exceptions.SodiumException;
import com.goterl.lazycode.lazysodium.interfaces.Box;
import com.goterl.lazycode.lazysodium.interfaces.Sign;

public class Utils
{
    /**
     * Zeros memory at the given bytep[] range
     * @param data
     * @return Returns true if memory could be securely zeroed
     */
    public static boolean zero(byte[] data)
    {
        LazySodiumJava sodium = new LazySodiumJava(new SodiumJava());

        sodium.getSodium().sodium_memzero(data, data.length);
        for (int i = 0; i < data.length; i++) {
            if (data[i] != 0) {
                return false;
            }
        }

        return true;
    }

    /**
     * Returns a crypto box keypair (32 byte secret, 32 byte public)
     * @return com.ncryptf.Keypair
     */
    public static Keypair generateKeypair()
    {
        try {
            LazySodiumJava sodium = new LazySodiumJava(new SodiumJava());

            Box.Lazy box = (Box.Lazy) sodium;
            com.goterl.lazycode.lazysodium.utils.KeyPair kp = box.cryptoBoxKeypair();

            return new Keypair(
                kp.getSecretKey().getAsBytes(),
                kp.getPublicKey().getAsBytes()
            );
        } catch (SodiumException e) {
            return null;
        }
    }

    /**
     * Returns a crypto sign keypair (64 byte secret, 32 byte public)
     * @return com.ncryptf.Keypair
     */
    public static Keypair generateSigningKeypair()
    {
        try {
            LazySodiumJava sodium = new LazySodiumJava(new SodiumJava());

            Sign.Lazy sign = (Sign.Lazy) sodium;
            com.goterl.lazycode.lazysodium.utils.KeyPair kp = sign.cryptoSignKeypair();

            return new Keypair(
                kp.getSecretKey().getAsBytes(),
                kp.getPublicKey().getAsBytes()
            );
        } catch (SodiumException e) {
            return null;
        }
    }
}