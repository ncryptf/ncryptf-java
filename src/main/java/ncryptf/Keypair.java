package ncryptf;

public class Keypair
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
     * @param secretKey
     * @param publicKey
     */
    public Keypair(byte[] secretKey, byte[] publicKey)
    {
        this.secretKey = secretKey;
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