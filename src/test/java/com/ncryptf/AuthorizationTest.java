package com.ncryptf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;

import com.ncryptf.exceptions.KeyDerivationException;

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

                assertEquals(this.v1HMACHeaders[index++], auth.getHeader());
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

                assertEquals(this.v2HMACHeaders[index++], auth.getHeader());
            } catch (KeyDerivationException e) {
                fail(e);
            }
        }
    }
}
