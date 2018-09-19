# ncryptf Java

[![TravisCI](https://img.shields.io/travis/charlesportwoodii/ncryptf-java.svg?style=flat-square "TravisCI")](https://travis-ci.org/charlesportwoodii/ncryptf-java)
[![License](https://img.shields.io/badge/license-BSD-orange.svg?style=flat-square "License")](https://github.com/charlesportwoodii/ncryptf-php/blob/master/LICENSE.md)

<center>
    <img src="https://github.com/charlesportwoodii/ncryptf-java/blob/master/logo.png?raw=true" alt="ncryptf logo" width="400px"/>
</center>

A library for facilitating hashed based KDF signature authentication, and end-to-end encrypted communication with compatible API's.

## Installing

This library can be installed via Maven or Gradle via a JitPack checkout:

### Maven

1. Add `jitpack.io` as a repository dependency in your `pom.xml`.
```xml
<repository>
    <id>jitpack.io</id>
    <url>https://jitpack.io</url>
</repository>
```

2. Add this repository as a dependency. Be sure to replace `LATEST_TAG_FROM_GITHUB` appropriately.
```xml
<dependency>
    <groupId>com.github.charlesportwoodii</groupId>
    <artifactId>ncryptf-java</artifactId>
    <version>LATEST_TAG_FROM_GITHUB</version>
</dependency>
```

### Gradle

1. Add `jitpack.io` to your root `bundle.gradle` file:
```json
allprojects {
    repositories {
        ...
        maven { url 'https://jitpack.io' }
    }
}
```

2. Add this repository as a dependency. Be sure to replace `LATEST_TAG_FROM_GITHUB` appropriately.
```json
dependencies {
    implementation 'com.github.charlesportwoodii:ncryptf-java:LATEST_TAG_FROM_GITHUB'
}
```

## Testing

```
mvn clean install -U
mvn test -B
```

## HMAC+HKDF Authentication

HMAC+HKDF Authentication is an Authentication method that allows ensures the request is not tampered with in transit. This provides resiliance not only against network layer manipulation, but also man-in-the-middle attacks.

At a high level, an HMAC signature is created based upon the raw request body, the HTTP method, the URI (with query parameters, if present), and the current date. In addition to ensuring the request cannot be manipulated in transit, it also ensures that the reqest is timeboxed, effectively preventing replay attacks.

The library itself is made available by importing the following struct:

Supporting API's will return the following payload containing at minimum the following information.

```json
{
    "access_token": "7XF56VIP7ZQQOLGHM6MRIK56S2QS363ULNB5UKNFMJRQVYHQH7IA",
    "refresh_token": "MA2JX5FXWS57DHW4OIHHQDCJVGS3ZKKFCL7XM4GNOB567I6ER4LQ",
    "ikm": "bDEyECRvKKE8w81fX4hz/52cvHsFPMGeJ+a9fGaVvWM=",
    "signing": "ecYXfAwNVoS9ePn4xWhiJOdXQzr6LpJIeIn4AVju/Ug=",
    "expires_at": 1472678411
}
```

After extracting the elements, we can create signed request by doing the following:

```java
import com.ncryptfToken;
import com.ncryptfAuthorization;
import com.ncryptfexceptions.*;

Token token = new Token(
    accessToken,
    refreshToken,
    ikm,
    signing,
    expiresAt
);

try {
    Authorization auth = new Authorization(
        httpMethod,
        uri,
        token,
        date,
        payload
    );

    String header = auth.getHeader();
} catch (KeyDerivationException e) {
    // Handle errors
}
```

A trivial full example is shown as follows:

```java
import com.ncryptfToken;
import com.ncryptfAuthorization;
import com.ncryptfexceptions.*;
import org.apache.commons.codec.binary.Base64;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

Token token = new Token(
    "7XF56VIP7ZQQOLGHM6MRIK56S2QS363ULNB5UKNFMJRQVYHQH7IA",
    "7XF56VIP7ZQQOLGHM6MRIK56S2QS363ULNB5UKNFMJRQVYHQH7IA",
    Base64.decodeBase64("bDEyECRvKKE8w81fX4hz/52cvHsFPMGeJ+a9fGaVvWM="),
    Base64.decodeBase64("ecYXfAwNVoS9ePn4xWhiJOdXQzr6LpJIeIn4AVju/Ug="),
    ZonedDateTime.ofInstant(Instant.ofEpochSecond(1472678411), ZoneOffset.UTC)
)

ZonedDateTime date = ZonedDateTime.now(ZoneOffset.UTC);

try {
    Authorization auth = new Authorization(
        "POST",
        "/api/v1/test",
        token,
        date,
        "{\"foo\":\"bar\"}"
    );

    String header = auth.getHeader();
} catch (KeyDerivationException e) {
    // Handle errors
}
```

> Note that the `date` property should be pore-offset when calling `Authorization` to prevent time skewing.

The `payload` parameter should be a JSON serializable string.

### Version 2 HMAC Header

The Version 2 HMAC header, for API's that support it can be retrieved by calling:

```java
String header = auth.getHeader();
```

### Version 1 HMAC Header

For API's using version 1 of the HMAC header, call `Authorization` with the optional `version` parameter set to `1` for the 6th parameter.

```java
try {
    Authorization auth = new Authorization(
        httpMethod,
        uri,
        token,
        date,
        payload,
        1
    );

    String header = auth.getHeader();
} catch (KeyDerivationException e) {
    // Handle errors
}
```

This string can be used in the `Authorization` Header

#### Date Header

The Version 1 HMAC header requires an additional `X-Date` header. The `X-Date` header can be retrieved by calling `auth.getDateString()`

## Encrypted Requests & Responses

This library enables clients coding in PHP 7.1+ to establish and trusted encrypted session on top of a TLS layer, while simultaniously (and independently) providing the ability authenticate and identify a client via HMAC+HKDF style authentication.

The rationale for this functionality includes but is not limited to:

1. Necessity for extra layer of security
2. Lack of trust in the network or TLS itself (see https://blog.cloudflare.com/incident-report-on-memory-leak-caused-by-cloudflare-parser-bug/)
3. Need to ensure confidentiality of the Initial Key Material (IKM) provided by the server for HMAC+HKDF authentication
4. Need to ensure confidentiality of user submitted credentials to the API for authentication

The primary reason you may want to establish an encrypted session with the API itself is to ensure confidentiality of the IKM to prevent data leakages over untrusted networks to avoid information being exposed in a Cloudflare like incident (or any man-in-the-middle attack). Encrypted sessions enable you to utilize a service like Cloudflare should a memory leak occur again with confidence that the IKM and other secure data would not be exposed.

To encrypt, decrypt, sign, and verify messages, you'll need to be able to generate the appropriate keys. Internally, this library uses [lazysodium-java](https://github.com/terl/lazysodium-java) to perform all necessary cryptography functions, though any libsodium implementation for Java would suffice.

#### Encryption Keys

Encryption uses a sodium crypto box. A keypair can be generated as follows when using `lazy-sodium`.

```java
import com.ncryptfUtils;
import com.ncryptfKeypair;
Keypair kp = Utils.generateKeypair();
```

#### Signing Keys

Encryption uses a sodium signature. A keypair for signing can be generated as follows using `lazy-sodium`:

```java
import com.ncryptfUtils;
import com.ncryptfKeypair;
Keypair kp = Utils.generateSigningKeypair();
```

### Encrypted Request Body

Payloads can be encrypted as follows:

```java
import com.ncryptfRequest;
import com.ncryptfexceptions.*;
import org.apache.commons.codec.binary.Base64;

// Arbitrary string payload
String payload = "{\"foo\":\"bar\"}";

try {
    // 32 byte secret and public key. Extract from kp.get...().getAsBytes(), or another libsodium method
    Request request = new Request(secretKeyBytes, publicKeyBytes);

    // Cipher now contains the encryted data
    // Signature should be the signature private key previously agreed upon with the sender
    // If you're using a `Token` object, this should be the `.signature` property
    byte[] cipher = request.encrypt(payload, token.signature);

    // Send as encrypted request body
    String b64Body = Base64.getEncoder().encode(cipher);

    // Do your http request here
} catch (EncryptionFailedException e) {
    // Handle encryption errors here
}
```

> Note that you need to have a pre-bootstrapped public key to encrypt data. For the v1 API, this is typically this is returned by `/api/v1/server/otk`.

### Decrypting Responses

Responses from the server can be decrypted as follows:

```java
import com.ncryptfResponse;
import com.ncryptfexceptions.*;
import org.apache.commons.codec.binary.Base64;

try {
    // Grab the raw response from the server
    byte[] responseFromServer = Base64.decodeBase64("<HTTP-Response-Body>");
    byte[] xnonce = Base64.decodeBase64("<X-Nonce-Header>");
    Response response = new Response(clientSecretKey);

    String decrypted = response.decrypt(responseFromServer);
} catch (InvalidChecksumException e) {
    // Checksum is not valid. Request body was tampered with
} catch (InvalidSignatureException e) {
    // Signature verification failed
} catch (DecryptionFailedException e) {
    // Decryption failed. This may be an issue with the provided nonce, or keypair being used
}
```

### V2 Encrypted Payload

Verison 2 works identical to the version 1 payload, with the exception that all components needed to decrypt the message are bundled within the payload itself, rather than broken out into separate headers. This alleviates developer concerns with needing to manage multiple headers.

The version 2 payload is described as follows. Each component is concatanated together.

| Segment | Length |
|---------|--------|
| 4 byte header `DE259002` in binary format | 4 BYTES |
| Nonce | 24 BYTES |
| The public key associated to the private key | 32 BYTES |
| Encrypted Body | X BYTES |
| Signature Public Key | 32 BYTES |
| Signature or raw request body | 64 BYTES |
| Checksum of prior elements concatonated together | 64 bytes |
