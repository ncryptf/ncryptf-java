package ncryptf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.SodiumJava;

import org.junit.jupiter.api.Test;

import ncryptf.Utils;
import ncryptf.Keypair;

public class UtilsTest
{
    @Test
    void testKeypairGeneration()
    {
        Keypair kp = Utils.generateKeypair();
        assertEquals(32, kp.getPublicKey().length);
        assertEquals(32, kp.getSecretKey().length);
    }

    @Test
    void testSigningKeypairGeneration()
    {
        Keypair kp = Utils.generateSigningKeypair();
        assertEquals(32, kp.getPublicKey().length);
        assertEquals(64, kp.getSecretKey().length);
    }

    @Test
    void testZero()
    {
        LazySodiumJava sodium = new LazySodiumJava(new SodiumJava());
        byte[] data = sodium.randomBytesBuf(32);
        boolean zero = Utils.zero(data);
        assertEquals(true, zero);
        for (int i = 0; i < data.length; i++) {
            assertEquals(0, data[i]);
        }
    }
}