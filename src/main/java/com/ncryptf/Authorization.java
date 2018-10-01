package com.ncryptf;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.SodiumJava;
import com.ncryptf.exceptions.KeyDerivationException;

import org.apache.commons.codec.binary.Hex;

import at.favre.lib.crypto.HKDF;

final public class Authorization
{
    /**
     * Default AUTH_INFO
     */
    public static final String AUTH_INFO = "HMAC|AuthenticationKey";

    /**
     * Token
     */
    private Token token;

    /**
     * 32 byte salt
     */
    private byte[] salt;

    /**
     * ZonedDateTime
     */
    private ZonedDateTime date;

    /**
     * Generated signature string
     */
    private String signature;

    /**
     * Generated HMAC
     */
    private byte[] hmac;

    /**
     * The default version to use for auth & signautres
     */
    private int version = 2;
    
    /**
     * Libsodium implementation
     */
    private LazySodiumJava sodium;

    /**
     * Constructor
     * 
     * @param httpMethod    The HTTP method
     * @param uri           The URI with query string parameters
     * @param token         A Token object
     * @param date          A ZonedDateTime object
     * @param payload       String payload
     * @throws KeyDerivationException If the authorization object cannot be generated
     */
    public Authorization(String httpMethod, String uri, Token token, ZonedDateTime date, String payload) throws KeyDerivationException
    {
        this(httpMethod, uri, token, date, payload, 2);
    }

    /**
     * Constructor
     * 
     * @param httpMethod    The HTTP method
     * @param uri           The URI with query string parameters
     * @param token         A Token object
     * @param date          A ZonedDateTime object
     * @param payload       String payload
     * @param version       The version to generate
     * @throws KeyDerivationException If the authorization object cannot be generated
     */
    public Authorization(String httpMethod, String uri, Token token, ZonedDateTime date, String payload, int version) throws KeyDerivationException
    {
        this(httpMethod, uri, token, date, payload, version, null);
    }

    /**
     * Constructor
     * 
     * @param httpMethod    The HTTP method
     * @param uri           The URI with query string parameters
     * @param token         A Token object
     * @param date          A ZonedDateTime object
     * @param payload       String payload
     * @param version       The version to generate
     * @param salt          Optional 32 byte fixed salt value
     * @throws KeyDerivationException If the authorization object cannot be generated
     */
    public Authorization(String httpMethod, String uri, Token token, ZonedDateTime date, String payload, int version, byte[] salt) throws KeyDerivationException
    {
        this.sodium = new LazySodiumJava(new SodiumJava());
        httpMethod = httpMethod.toUpperCase();
        if (salt == null) {
            salt = this.sodium.randomBytesBuf(32);
        }

        this.salt = salt;
        this.signature = Signature.derive(httpMethod, uri, salt, date, payload, version);
        this.date = date;
        this.version = version;
        this.token = token;

        byte[] hkdf = HKDF.fromHmacSha256().expand(
            HKDF.fromHmacSha256().extract(salt, token.ikm),
            AUTH_INFO.getBytes(),
            32
        );        
        
        try {
            String hkdfString = new String(Hex.encodeHex(hkdf));
            byte[] key = (hkdfString).toLowerCase().getBytes("UTF-8");
            byte[] sig = (this.signature).getBytes("UTF-8");

            Mac HMAC = Mac.getInstance("HMACSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(key, "HMACSHA256");

            HMAC.init(secretKey);
            this.hmac = HMAC.doFinal(sig);
        } catch (NoSuchAlgorithmException | InvalidKeyException | UnsupportedEncodingException e) {
            throw new KeyDerivationException();
        }
    }

    /**
     * @return Returns the ZonedDateTime used
     */
    public ZonedDateTime getDate()
    {
        return date;
    }

    /**
     * @return Returns the raw date string used
     */
    public String getDateString()
    {
        return DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss Z").format(this.date).replaceAll(" GMT", " +0000");
    }

    /**
     * @return Returns the calculated HMAC
     */
    public byte[] getHMAC()
    {
        return this.hmac;
    }

    /**
     * @return Returns the base64 encoded HMAc
     */
    public String getEncodedHMAC()
    {
        return Base64.getEncoder().encodeToString(this.hmac);
    }

    /**
     * @return Returns the base64 encoded salt
     */
    public String getEncodedSalt()
    {
        return Base64.getEncoder().encodeToString(this.salt);
    }

    /**
     * @return Returns the calculated signature string
     */
    public String getSignatureString()
    {
        return this.signature;
    }

    /**
     * Returns the versioned header string
     * @return The versioned header string
     */
    public String getHeader()
    {
        String salt = this.getEncodedSalt();
        String hmac = this.getEncodedHMAC();

        if (this.version == 2) {
            String json = "{\"access_token\":\"" + this.token.accessToken + "\",\"date\":\"" + this.getDateString() + "\",\"hmac\":\"" + hmac +"\",\"salt\":\"" + salt + "\",\"v\":2}";
            json = json.replace("/", "\\/");

            try {
                String b64 = Base64.getEncoder().encodeToString(json.getBytes("UTF-8"));
                return "HMAC " + b64;
            } catch (UnsupportedEncodingException e) {
                return "";
            }            
        }

        return "HMAC " + this.token.accessToken + "," + hmac + "," + salt;
    }

    /**
     * Validates a provided HMAC against an auth object and a drift
     *
     * @param hmac 32 byte HMAC
     * @param auth Authorization object generated from HTTP request
     * @return boolean
     */
    public Boolean verify(byte[] hmac, Authorization auth)
    {
        return this.verify(hmac, auth, 90);
    }

    /**
     * Validates a provided HMAC against an auth object and a drift
     *
     * @param hmac 32 byte HMAC
     * @param auth Authorization object generated from HTTP request
     * @param driftAllowance Number of seconds that the request may be permitted to drift by
     * @return boolean
     */
    public Boolean verify(byte[] hmac, Authorization auth, Integer driftAllowance)
    {
        Integer drift = this.getTimeDrift(auth.getDate());
        if (drift >= driftAllowance) {
            return false;
        }

        // Constant time byte comparison between the provided hmac and the authorization object
        if (this.sodium.getSodium().sodium_memcmp(hmac, auth.getHMAC(), 32) == 0) {
            return true;
        }

        return false;
    }

    /**
     * Calculates the time difference between now and the provided date
     * @param date The date to compare against
     * @return Integer
     */
    private Integer getTimeDrift(ZonedDateTime date)
    {
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);

        return (int)Math.abs(now.toEpochSecond() - date.toEpochSecond());
    }
}