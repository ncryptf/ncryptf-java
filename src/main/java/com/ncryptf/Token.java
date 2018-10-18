package com.ncryptf;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;

import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.SodiumJava;

final public class Token
{
    /**
     * The access token
     */
    public String accessToken;

    /**
     * The refresh token
     */
    public String refreshToken;

    /**
     * 32 byte initial key material
     */
    public byte[] ikm;

    /**
     * The signature bytes
     */
    public byte[] signature;

    /**
     * The token expiration time
     */
    public long expiresAt;

    /**
     * Constructor
     *
     * @param accessToken   The access token returned by the server
     * @param refreshToken  The refresh token returned by the server
     * @param ikm           32 byte initial key material returned by the server
     * @param signature     Byte signature returned by the server
     * @param expiresAt     Double time at which the token expires at
     */
    public Token(String accessToken, String refreshToken, byte[] ikm, byte[] signature, long expiresAt)
    {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.ikm = ikm;
        this.signature = signature;
        this.expiresAt = expiresAt;
    }

    /**
     * @return Returns `true` if the ecurent token is expired and should be refreshed
     */
    public Boolean isExpired()
    {
        long now = ZonedDateTime.now(ZoneOffset.UTC).toEpochSecond();
        return now > this.expiresAt;
    }

    /**
     * Extracts the signature public key from the provided private key
     * @return byte[]
     */
    public byte[] getSignaturePublicKey()
    {
        LazySodiumJava sodium = new LazySodiumJava(new SodiumJava());
        byte[] publicKey = new byte[32];
        if (sodium.getSodium().crypto_sign_ed25519_sk_to_pk(publicKey, this.signature) != 0) {
            return null;
        }

        return publicKey;
    }
}