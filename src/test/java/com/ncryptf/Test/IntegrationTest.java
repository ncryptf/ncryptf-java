package com.ncryptf.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.platform.commons.util.StringUtils;

import okhttp3.OkHttpClient;
import okhttp3.RequestBody;
import okhttp3.Request.Builder;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Base64;

import com.ncryptf.*;
import org.json.JSONObject;

import java.time.ZonedDateTime;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.condition.DisabledIf;

import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.SodiumJava;

/**
 * This class demonstrates a practical end-to-end implementation via cURL
 * Implementation may be inferred from this implementation, and is broken out into the following stages:
 * 1. Create a \ncryptf\Keypair instance
 * 2. Bootstrap an encrypted session by sending an unauthenticated requests to the ephemeral key endpoint with the following headers:
 *  - Accept: application/vnd.ncryptf+json
 *  - Content-Type: application/vnd.ncryptf+json
 *  - X-PubKey: <base64_encoded_$key->getPublicKey()>
 * 3. Decrypt the V2 response from the server. This contains a single use ephemeral key we can use to encrypt future requests in the payload.
 *    The servers public key is embedded in the response, and can be extracted by `Response::getPublicKeyFromResponse($response);`
 * 4. Perform an authenticated request using the clients secret key, and the servers public key.
 *
 *
 * Implementation Details
 * - The server WILL always advertise at minimum the following 2 headers:
 *      - X-HashId: A string used to represent the identifier to use to select which key to use.
 *      - X-Public-Key-Expiration: A unix timestamp representing the time at which the key will expire. This is used to determine if rekeying is required.
 * - The server WILL always generate a new keypair for each request. You may continue to use existing keys until they expire.
 * - To achieve perfect-forward-secrecy, it is advised to rekey the client key on each request. The server does not store the shared secret for prior requests.
 * - The client SHOULD keep a record of public keys offered by the server, along with their expiration time.
 * - The client SHOULD always use the most recent key offered by the server.
 * - If the client does not have any active keys, it should bootstrap a new session by calling the ephemeral key endpoint to retrieve a new public key from the server.
 */
@TestInstance(Lifecycle.PER_CLASS)
public class IntegrationTest
{
    /**
     * This is the URL provided by the `NCRYPTF_TEST_API` environment variable.
     */
    private String url = "";

    /**
     * A keypair object
     */
    private Keypair key;

    /**
     * An optional access token to identify this client.
     */
    private String token = "";

    /**
     * Stack containing the public key hash identifier, and original message generated on bootstrap
     * This is a hack to get around the lack of shared states between tests.
     */
    private Object[] ephemeralKeyBootstrap;

    /**
     * Token generated from authenticated
     *This is a hack to get around the lack of shared states between tests.
     */
    private Token authToken;

    @BeforeAll
    void setUp()
    {
        String url;
        if (!StringUtils.isBlank(url = System.getenv("NCRYPTF_TEST_API"))) {
            this.url = url;
        }

        String token;
        if (!StringUtils.isBlank(token = System.getenv("ACCESS_TOKEN"))) {
            this.token = token;
        }

        this.key = Utils.generateKeypair();
    }

    /**
     * Tests the bootstrap process with an encrypted response
     * @return void
     */
    @Test
    @DisabledIf("'' == systemEnvironment.get('NCRYPTF_TEST_API') || null == systemEnvironment.get('NCRYPTF_TEST_API')")
    void testEphemeralKeyBootstrap()
    {
        OkHttpClient client = new OkHttpClient();

        try {
            Builder builder = new Builder()
                .addHeader("Accept", "application/vnd.ncryptf+json")
                .addHeader("Content-Type", "application/vnd.ncryptf+json")
                .url(this.url + "/ek");

            if (!StringUtils.isBlank(this.token)) {
                builder.addHeader("X-Access-Token", this.token);
            }

            // Tell the server what our public key is since our request body will be empty on GET
            builder.addHeader("x-pubkey", Base64.getEncoder().encodeToString(this.key.getPublicKey()));

            okhttp3.Request request = builder.build();
            okhttp3.Response response = client.newCall(request).execute();

            com.ncryptf.Response r = new com.ncryptf.Response(this.key.getSecretKey());

            assertEquals(200, response.code());

            byte[] responseBody = Base64.getDecoder().decode(response.body().string());
            String message = r.decrypt(responseBody);
            JSONObject json = new JSONObject(message);

            assertTrue(StringUtils.isNotBlank(message));
            assertTrue(StringUtils.isNotBlank(json.getString("public")));
            assertTrue(StringUtils.isNotBlank(json.getString("signature")));
            assertTrue(StringUtils.isNotBlank(json.getString("hash-id")));

            this.ephemeralKeyBootstrap = new Object[] {
                com.ncryptf.Response.getPublicKeyFromResponse(responseBody),
                response.headers().get("x-hashid"),
                message
            };
        } catch (Exception e) {
            fail(e.getMessage() + " " + e.getClass());
        }
    }

    /**
     * This requests illustrates making an unauthenticated encrypted request and receiving an encrypted response
     * @depends testEphemeralKeyBootstrap
     * @return void
     */
    @Test
    @DisabledIf("'' == systemEnvironment.get('NCRYPTF_TEST_API') || null == systemEnvironment.get('NCRYPTF_TEST_API')")
    void testUnauthenticatedEncryptedRequest()
    {
        this.testEphemeralKeyBootstrap();
        Object[] stack = this.ephemeralKeyBootstrap;

        OkHttpClient client = new OkHttpClient();

        try {
            Builder builder = new Builder()
                .addHeader("Accept", "application/vnd.ncryptf+json")
                .addHeader("Content-Type", "application/vnd.ncryptf+json")
                .url(this.url + "/echo");

            if (!StringUtils.isBlank(this.token)) {
                builder.addHeader("X-Access-Token", this.token);
            }

            // Tell the server what key we want to use
            builder.addHeader("X-HashId", (String)stack[1]);

            // Our public is is embedded in the signed request, so we don't need to explicitly tell
            // the server what our public key is via this header. Implementors may wish to always include this for convenience
            // If a public key is embedded in the body, it will supercede whatever is in the header.
            // builder.addHeader("x-pubkey", Base64.getEncoder().encodeToString(this.key.getPublicKey()));

            String payload = "{\"hello\":\"world\"}";

            com.ncryptf.Request req = new com.ncryptf.Request(
                this.key.getSecretKey(),
                // Because our request is unauthenticated, this signature doesn't mean anything, so we can just generate a random one.
                Utils.generateSigningKeypair().getSecretKey()
            );

            String encryptedPayload = Base64.getEncoder().encodeToString(
                req.encrypt(payload, (byte[])stack[0])
            );

            // Force okHttp not to mess with the encoding.
            builder.post(RequestBody.create(null, encryptedPayload));
            okhttp3.Request request = builder.build();
            okhttp3.Response response = client.newCall(request).execute();

            assertEquals(200, response.code());

            com.ncryptf.Response resp = new com.ncryptf.Response(this.key.getSecretKey());

            String rawResponseBody = response.body().string();
            byte[] responseBody = Base64.getDecoder().decode(rawResponseBody);
            String message = resp.decrypt(responseBody);

            // The echo endpoint should echo the same response back to use after decrypting it.
            assertEquals(payload, message);
        } catch (Exception e) {
            fail(e.getMessage() + " " + e.getClass());
        }
    }

    /**
     * This request securely authenticates a user with an encrypted request and returns an encrypted response
     * This request is encrypted end-to-end
     * @depends testEphemeralKeyBootstrap
     * @return void
     */
    @Test
    @DisabledIf("'' == systemEnvironment.get('NCRYPTF_TEST_API') || null == systemEnvironment.get('NCRYPTF_TEST_API')")
    void testAuthenticateWithEncryptedRequest()
    {
        this.testEphemeralKeyBootstrap();
        Object[] stack = this.ephemeralKeyBootstrap;

        OkHttpClient client = new OkHttpClient();

        try {
            Builder builder = new Builder()
                .addHeader("Accept", "application/vnd.ncryptf+json")
                .addHeader("Content-Type", "application/vnd.ncryptf+json")
                .url(this.url + "/authenticate");

            if (!StringUtils.isBlank(this.token)) {
                builder.addHeader("X-Access-Token", this.token);
            }

            // Tell the server what key we want to use
            builder.addHeader("X-HashId", (String)stack[1]);

            // Our public is is embedded in the signed request, so we don't need to explicitly tell
            // the server what our public key is via this header. Implementors may wish to always include this for convenience
            // If a public key is embedded in the body, it will supercede whatever is in the header.
            // builder.addHeader("x-pubkey", Base64.getEncoder().encodeToString(this.key.getPublicKey()));

            String payload = "{\"email\":\"clara.oswald@example.com\",\"password\":\"c0rect h0rs3 b@tt3y st@Pl3\"}";

            com.ncryptf.Request req = new com.ncryptf.Request(
                this.key.getSecretKey(),
                // Because our request is unauthenticated, this signature doesn't mean anything, so we can just generate a random one.
                Utils.generateSigningKeypair().getSecretKey()
            );

            String encryptedPayload = Base64.getEncoder().encodeToString(
                req.encrypt(payload, (byte[])stack[0])
            );

            // Force okHttp not to mess with the encoding.
            builder.post(RequestBody.create(null, encryptedPayload));
            okhttp3.Request request = builder.build();
            okhttp3.Response response = client.newCall(request).execute();

            assertEquals(200, response.code());

            com.ncryptf.Response resp = new com.ncryptf.Response(this.key.getSecretKey());

            String rawResponseBody = response.body().string();
            byte[] responseBody = Base64.getDecoder().decode(rawResponseBody);
            String message = resp.decrypt(responseBody);

            JSONObject json = new JSONObject(message);

            assertTrue(StringUtils.isNotBlank(message));
            assertTrue(StringUtils.isNotBlank(json.getString("access_token")));
            assertTrue(StringUtils.isNotBlank(json.getString("refresh_token")));
            assertTrue(StringUtils.isNotBlank(json.getString("ikm")));
            assertTrue(StringUtils.isNotBlank(json.getString("signing")));
            assertTrue(StringUtils.isNotBlank(String.valueOf(json.getInt("expires_at"))));

            this.authToken = new Token(
                json.getString("access_token"),
                json.getString("refresh_token"),
                Base64.getDecoder().decode(json.getString("ikm")),
                Base64.getDecoder().decode(json.getString("signing")),
                (long)json.getInt("expires_at")
            );

        } catch (Exception e) {
            fail(e.getMessage() + " " + e.getClass());
        }
    }

    /**
     * This request securely authenticates a user with an encrypted request and returns an encrypted response
     * This request is encrypted end-to-end
     * @depends testEphemeralKeyBootstrap
     * @return void
     */
    @Test
    @DisabledIf("'' == systemEnvironment.get('NCRYPTF_TEST_API') || null == systemEnvironment.get('NCRYPTF_TEST_API')")
    void testAuthenticatedEchoWithEncryptedRequest()
    {
        this.testAuthenticateWithEncryptedRequest();
        Object[] stack = this.ephemeralKeyBootstrap;
        Token token = this.authToken;

        OkHttpClient client = new OkHttpClient();

        try {
            Builder builder = new Builder()
                .addHeader("Accept", "application/vnd.ncryptf+json")
                .addHeader("Content-Type", "application/vnd.ncryptf+json")
                .url(this.url + "/echo");

            if (!StringUtils.isBlank(this.token)) {
                builder.addHeader("X-Access-Token", this.token);
            }

            // Tell the server what key we want to use
            builder.addHeader("X-HashId", (String)stack[1]);

            // Our public is is embedded in the signed request, so we don't need to explicitly tell
            // the server what our public key is via this header. Implementors may wish to always include this for convenience
            // If a public key is embedded in the body, it will supercede whatever is in the header.
            // builder.addHeader("x-pubkey", Base64.getEncoder().encodeToString(this.key.getPublicKey()));

            String payload = "{\"hello\":\"world\"}";

            com.ncryptf.Request req = new com.ncryptf.Request(
                this.key.getSecretKey(),
                // Authenticated requests enforce the that the request was made by us by signing it with the signature provided by the API.
                token.signature
            );

            String encryptedPayload = Base64.getEncoder().encodeToString(
                req.encrypt(payload, (byte[])stack[0])
            );

            Authorization auth = new Authorization(
                "PUT",
                "/echo",
                token,
                ZonedDateTime.now(),
                payload
            );

            builder.addHeader("Authorization", auth.getHeader());

            // Force okHttp not to mess with the encoding.
            builder.put(RequestBody.create(null, encryptedPayload));
            okhttp3.Request request = builder.build();
            okhttp3.Response response = client.newCall(request).execute();

            assertEquals(200, response.code());

            com.ncryptf.Response resp = new com.ncryptf.Response(this.key.getSecretKey());

            String rawResponseBody = response.body().string();
            byte[] responseBody = Base64.getDecoder().decode(rawResponseBody);
            String message = resp.decrypt(responseBody);

             /**
             * As an added integrity check, the API will sign the message with the same key it issued during authentication
             * Therefore, we can verify that the signing public key associated to the message matches the public key from the
             * token we were issued.
             *
             * If the keys match, then we have assurance that the message is authenticated
             * If the keys don't match, then the request has been tampered with and should be discarded.
             *
             * This check should ALWAYS be performed for authenticated requests as it ensures the validity of the message
             * and the origin of the message.
             */
            LazySodiumJava sodium = new LazySodiumJava(new SodiumJava());
            assertTrue(
                sodium.getSodium().sodium_memcmp(
                    token.getSignaturePublicKey(),
                    com.ncryptf.Response.getSigningPublicKeyFromResponse(responseBody),
                    32
                ) == 0
            );

            // The echo endpoint should echo the same response back to use after decrypting it.
            assertEquals(payload, message);
        } catch (Exception e) {
            fail(e.getMessage() + " " + e.getClass());
        }
    }

    /************************************************************************************************
     *
     * The requests that follow are for implementation sanity checks, and should not be referenced
     * for other client implementations
     *
     ************************************************************************************************/

    /**
     * De-authenticates a user via an encrypted and authenticated request
     * @depends testAuthenticateWithEncryptedRequest
     * @return void
     */
    @Test
    @DisabledIf("'' == systemEnvironment.get('NCRYPTF_TEST_API') || null == systemEnvironment.get('NCRYPTF_TEST_API')")
    void testAuthenticatedEchoWithBadSignature()
    {
        this.testAuthenticateWithEncryptedRequest();
        Object[] stack = this.ephemeralKeyBootstrap;
        Token token = this.authToken;

        OkHttpClient client = new OkHttpClient();

        try {
            Builder builder = new Builder()
                .addHeader("Accept", "application/vnd.ncryptf+json")
                .addHeader("Content-Type", "application/vnd.ncryptf+json")
                .url(this.url + "/echo");

            if (!StringUtils.isBlank(this.token)) {
                builder.addHeader("X-Access-Token", this.token);
            }

            // Tell the server what key we want to use
            builder.addHeader("X-HashId", (String)stack[1]);

            // Our public is is embedded in the signed request, so we don't need to explicitly tell
            // the server what our public key is via this header. Implementors may wish to always include this for convenience
            // If a public key is embedded in the body, it will supercede whatever is in the header.
            // builder.addHeader("x-pubkey", Base64.getEncoder().encodeToString(this.key.getPublicKey()));

            String payload = "{\"hello\":\"world\"}";

            com.ncryptf.Request req = new com.ncryptf.Request(
                this.key.getSecretKey(),
                // Generating a random key instead of using the one issued to us will result in a signature failure
                Utils.generateSigningKeypair().getSecretKey()
            );

            String encryptedPayload = Base64.getEncoder().encodeToString(
                req.encrypt(payload, (byte[])stack[0])
            );

            Authorization auth = new Authorization(
                "PUT",
                "/echo",
                token,
                ZonedDateTime.now(),
                payload
            );

            builder.addHeader("Authorization", auth.getHeader());

            // Force okHttp not to mess with the encoding.
            builder.put(RequestBody.create(null, encryptedPayload));
            okhttp3.Request request = builder.build();
            okhttp3.Response response = client.newCall(request).execute();

            assertEquals(401, response.code());
        } catch (Exception e) {
            fail(e.getMessage() + " " + e.getClass());
        }
    }

    /**
     * Verifies that a tampered request results in an error.
     * @depends testEphemeralKeyBootstrap
     * @return void
     */
    @Test
    @DisabledIf("'' == systemEnvironment.get('NCRYPTF_TEST_API') || null == systemEnvironment.get('NCRYPTF_TEST_API')")
    void testMalformedEncryptedRequest()
    {
        this.testEphemeralKeyBootstrap();
        Object[] stack = this.ephemeralKeyBootstrap;

        OkHttpClient client = new OkHttpClient();

        try {
            Builder builder = new Builder()
                .addHeader("Accept", "application/vnd.ncryptf+json")
                .addHeader("Content-Type", "application/vnd.ncryptf+json")
                .url(this.url + "/echo");

            if (!StringUtils.isBlank(this.token)) {
                builder.addHeader("X-Access-Token", this.token);
            }

            // Tell the server what key we want to use
            builder.addHeader("X-HashId", (String)stack[1]);

            // Our public is is embedded in the signed request, so we don't need to explicitly tell
            // the server what our public key is via this header. Implementors may wish to always include this for convenience
            // If a public key is embedded in the body, it will supercede whatever is in the header.
            // builder.addHeader("x-pubkey", Base64.getEncoder().encodeToString(this.key.getPublicKey()));

            String payload = "{\"hello\":\"world\"}";

            com.ncryptf.Request req = new com.ncryptf.Request(
                this.key.getSecretKey(),
                // Generating a random key instead of using the one issued to us will result in a signature failure
                Utils.generateSigningKeypair().getSecretKey()
            );

            // Replace 32 bytes with zero to corrupt the payload
            byte[] rawPayload = req.encrypt(payload, (byte[])stack[0]);
            Arrays.fill(rawPayload, 60, 92, (byte)0);

            String encryptedPayload = Base64.getEncoder().encodeToString(
                rawPayload
            );
            // Force okHttp not to mess with the encoding.
            builder.put(RequestBody.create(null, encryptedPayload));
            okhttp3.Request request = builder.build();
            okhttp3.Response response = client.newCall(request).execute();

            assertEquals(400, response.code());
        } catch (Exception e) {
            fail(e.getMessage() + " " + e.getClass());
        }
    }
}