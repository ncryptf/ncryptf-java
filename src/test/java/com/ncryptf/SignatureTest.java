package com.ncryptf;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class SignatureTest extends AbstractTest
{
    @Test
    void testV1Signatures()
    {
        int index = 0;
        for (TestCase test : this.testCases) {
            String signature = Signature.derive(
                test.httpMethod,
                test.uri,
                this.salt,
                this.date,
                test.payload,
                1
            );
            String[] lines = signature.split("\\n");
            assertEquals(this.v1SignatureResults[index++], lines[0]);
        }
    }

    @Test
    void testV2Signatures()
    {
        int index = 0;
        for (TestCase test : this.testCases) {
            String signature = Signature.derive(
                test.httpMethod,
                test.uri,
                this.salt,
                this.date,
                test.payload,
                2
            );
            String[] lines = signature.split("\\n");
            assertEquals(this.v2SignatureResults[index++], lines[0]);
        }
    }
}
