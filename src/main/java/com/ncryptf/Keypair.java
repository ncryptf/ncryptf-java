package com.ncryptf;

final public class Keypair
{
    /**
     * Secret key bytes
     */
    private byte[] secretKey;

    /**
     * Public key bytes
     */
    private byte[] publicKey;

    /**
     * Constructor
     * @param secretKey     Secret key bytes
     * @param publicKey     Public key bytes
     */
    public Keypair(byte[] secretKey, byte[] publicKey)
    {
        if (secretKey.length % 16 != 0) {
            throw new IllegalArgumentException(String.format("Secret key should be a multiple of %d bytes.", 16));
        }
        
        this.secretKey = secretKey;

        if (publicKey.length % 4 != 0) {
            throw new IllegalArgumentException(String.format("Public key should be a multiple of %d bytes.", 4));
        }
        this.publicKey = publicKey;
    }

    /**
     * Returns the public key bytes
     * @return byte[]
     */
    public byte[] getPublicKey()
    {
        return this.publicKey;
    }

    /**
     * Returns the secret key bytes
     * @return byte[]
     */
    public byte[] getSecretKey()
    {
        return this.secretKey;
    }
}