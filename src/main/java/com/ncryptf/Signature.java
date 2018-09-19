package com.ncryptf;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.SodiumJava;
import com.goterl.lazycode.lazysodium.interfaces.GenericHash;

import org.apache.commons.codec.digest.DigestUtils;

public class Signature
{
    /**
     * Constructs a new v2 signature
     * 
     * @param httpMethod    The HTTP method
     * @param uri           The full URI with query string parameters
     * @param salt          32 byte salt
     * @param date          ZonedDateTime object
     * @param payload       String request body to sign
     * @return Version 2 signature
     */
    public static String derive(
        String httpMethod,
        String uri,
        byte[] salt,
        ZonedDateTime date,
        String payload
    ) {
        return derive(httpMethod, uri, salt, date, payload, 2);
    }

    /**
     * Constructs versioned signature
     * 
     * @param httpMethod    The HTTP method
     * @param uri           The full URI with query string parameters
     * @param salt          32 byte salt
     * @param date          ZonedDateTime object
     * @param payload       String request body to sign
     * @param version       The integer signature version
     * @return Versioned signatured
     */
    public static String derive(
        String httpMethod,
        String uri,
        byte[] salt,
        ZonedDateTime date,
        String payload,
        int version
    ) {
        httpMethod = httpMethod.toUpperCase();

        String hash = getSignatureHash(payload, salt, version);
        String b64Salt = new String(Base64.getEncoder().encode(salt));
        String timestamp = DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss Z").format(date).replaceAll(" GMT", " +0000");

        return hash + "\n" + 
               httpMethod + "+" + uri + "\n" +
               timestamp + "\n" +
               b64Salt;
    }

    /**
     * Returns the signature hash
     * 
     * @param data      The data to hash
     * @param salt      32 byte salt
     * @param version   The signature hash version to generate.
     * @return          A string epresenting the signature hash
     */
    private static String getSignatureHash(String data, byte[] salt, int version)
    {
        String hash;
        if (version == 2) {
            LazySodiumJava sodium = new LazySodiumJava(new SodiumJava());
            GenericHash.Native gh = (GenericHash.Native) sodium;
            byte[] h = new byte[64];
            byte[] dataBytes = data.getBytes();
            gh.cryptoGenericHash(
                h,
                h.length,
                dataBytes,
                dataBytes.length,
                salt,
                salt.length
            );

            hash = new String(Base64.getEncoder().encode(h));
        } else {
            hash = DigestUtils.sha256Hex(data).toLowerCase();
        }

        return hash;
    }
}