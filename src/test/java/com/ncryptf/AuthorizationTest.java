package com.ncryptf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;

import java.util.Base64;
import com.ncryptf.exceptions.KeyDerivationException;
import org.json.JSONObject;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;

public class AuthorizationTest extends AbstractTest
{
    @Test
    void testV1HMAC()
    {
        int index = 0;
        for (TestCase test : this.testCases) {
            try {
                Authorization auth = new Authorization(
                    test.httpMethod,
                    test.uri,
                    this.token,
                    this.date,
                    test.payload,
                    1,
                    this.salt
                );

                String header = this.v1HMACHeaders[index++];
                assertEquals(header, auth.getHeader());
                String[] r = header.split(",");
                byte[] hmac = Base64.getDecoder().decode(r[1]);
                assertEquals(false, auth.verify(hmac, auth, 90));
            } catch (KeyDerivationException e) {
                fail(e);
            }
        }
    }

    @Test
    void testV2HMAC()
    {
        int index = 0;
        for (TestCase test : this.testCases) {
            try {
                Authorization auth = new Authorization(
                    test.httpMethod,
                    test.uri,
                    this.token,
                    this.date,
                    test.payload,
                    2,
                    this.salt
                );

                String header = this.v2HMACHeaders[index++];
                assertEquals(header, auth.getHeader());
                JSONObject json = new JSONObject(new String(Base64.getDecoder().decode(header.replace("HMAC ", ""))));
                byte[] hmac = Base64.getDecoder().decode(json.getString("hmac"));
                assertEquals(false, auth.verify(hmac, auth, 90));
            } catch (KeyDerivationException e) {
                fail(e);
            }
        }
    }

    @Test
    void testVerify()
    {
        for (TestCase test : this.testCases) {
            try {
                Authorization auth = new Authorization(
                    test.httpMethod,
                    test.uri,
                    this.token,
                    ZonedDateTime.now(ZoneOffset.UTC),
                    test.payload,
                    1,
                    this.salt
                );

                assertEquals(true, auth.verify(auth.getHMAC(), auth, 90));

                Authorization auth2 = new Authorization(
                    test.httpMethod,
                    test.uri,
                    this.token,
                    ZonedDateTime.now(ZoneOffset.UTC),
                    test.payload,
                    2,
                    this.salt
                );

                assertEquals(true, auth2.verify(auth2.getHMAC(), auth, 90));
            } catch (KeyDerivationException e) {
                fail(e);
            }
        }
    }
}
