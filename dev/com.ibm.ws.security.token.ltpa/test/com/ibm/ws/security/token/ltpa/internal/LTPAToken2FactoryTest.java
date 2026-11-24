/*******************************************************************************
 * Copyright (c) 2011, 2026 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.security.token.ltpa.internal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

import com.ibm.websphere.security.auth.TokenCreationFailedException;
import com.ibm.ws.common.encoder.Base64Coder;
import com.ibm.ws.crypto.ltpakeyutil.LTPAPrivateKey;
import com.ibm.ws.crypto.ltpakeyutil.LTPAPublicKey;
import com.ibm.ws.security.token.ltpa.LTPAKeyInfoManager;
import com.ibm.wsspi.security.ltpa.Token;
import com.ibm.wsspi.security.ltpa.TokenFactory;

import com.ibm.ws.security.token.ltpa.LTPAKeyInfoManagerTestUtil;
import test.common.SharedOutputManager;

/**
 *
 */
public class LTPAToken2FactoryTest {

    private static SharedOutputManager outputMgr = SharedOutputManager.getInstance();
    /**
     * Using the test rule will drive capture/restore and will dump on error..
     * Notice this is not a static variable, though it is being assigned a value we
     * allocated statically. -- the normal-variable-ness is for before/after processing
     */
    @Rule
    public TestRule managerRule = outputMgr;

    private static final String KEYIMPORTFILE_CORRECT = "${server.config.dir}/resources/security/security.token.ltpa.keys.correct.txt";
    private static final byte[] KEYPASSWORD_CORRECT = "WebAS".getBytes();
    private static final String decodedSharedKey = "Three can keep a secret when two are no longer there";
    private static final String encodedSharedKey = Base64Coder.base64Encode(decodedSharedKey);
    private LTPAPrivateKey ltpaPrivateKey;
    private LTPAPublicKey ltpaPublicKey;
    private Map<String, Object> tokenFactoryMap;
    private TokenFactory tokenFactory;

    @Before
    public void setUp() throws Exception {
        setupLTPAKeys();
        tokenFactoryMap = createTestTokenFactoryMap();
        tokenFactory = createInitializedTokenFactory(tokenFactoryMap);
    }

    private void setupLTPAKeys() throws Exception {
        LTPAKeyInfoManager keyInfoManager = new LTPAKeyInfoManager();
        LTPAKeyInfoManagerTestUtil.prepareClassical(keyInfoManager, KEYIMPORTFILE_CORRECT, KEYPASSWORD_CORRECT, null, false);
        ltpaPrivateKey = new LTPAPrivateKey(keyInfoManager.getPrivateKey(KEYIMPORTFILE_CORRECT));
        ltpaPublicKey = new LTPAPublicKey(keyInfoManager.getPublicKey(KEYIMPORTFILE_CORRECT));
    }

    private Map<String, Object> createTestTokenFactoryMap() {
        long expectedExpirationLimit = 120;
        long expDiffAllowed = 0;
        Map<String, Object> tokenFactoryMap = new HashMap<String, Object>();
        tokenFactoryMap.put("expiration", expectedExpirationLimit);
        tokenFactoryMap.put("primary_ltpa_shared_key", encodedSharedKey.getBytes());
        tokenFactoryMap.put("primary_ltpa_public_key", ltpaPublicKey);
        tokenFactoryMap.put("primary_ltpa_private_key", ltpaPrivateKey);
        tokenFactoryMap.put("expirationDifferenceAllowed", expDiffAllowed);

        return tokenFactoryMap;
    }

    private LTPAToken2Factory createInitializedTokenFactory(Map<String, Object> tokenFactoryMap) {
        LTPAToken2Factory tokenFactory = new LTPAToken2Factory();
        tokenFactory.initialize(tokenFactoryMap);
        return tokenFactory;
    }

    @Test
    public void testConstructor() {
        TokenFactory tokenFactory = new LTPAToken2Factory();
        assertNotNull("There must be a token factory.", tokenFactory);
    }

    @Test
    public void testInitializeSetsExpirationLimit() throws Exception {
        long expectedExpirationLimit = (Long) tokenFactoryMap.get("expiration");
        Field expirationInMinutesField = LTPAToken2Factory.class.getDeclaredField("expirationInMinutes");
        expirationInMinutesField.setAccessible(true);
        long actualExpirationInMinutes = expirationInMinutesField.getLong(tokenFactory);

        assertEquals("The expiration in minutes must be equals to the expected expiration limit.", expectedExpirationLimit, actualExpirationInMinutes);
    }

    @Test
    public void testInitializeSetsSharedKey() throws Exception {
        byte[] expectedSharedKey = (byte[]) tokenFactoryMap.get("primary_ltpa_shared_key");
        Field sharedKeyField = LTPAToken2Factory.class.getDeclaredField("primarySharedKey");
        sharedKeyField.setAccessible(true);
        byte[] actualSharedKey = (byte[]) sharedKeyField.get(tokenFactory);

        assertEquals("The shared key must be equals to the expected shared key.", expectedSharedKey, actualSharedKey);
    }

    @Test
    public void testInitializeSetsPublicKey() throws Exception {
        LTPAPublicKey expectedPublicKey = (LTPAPublicKey) tokenFactoryMap.get("primary_ltpa_public_key");
        Field publicKeyField = LTPAToken2Factory.class.getDeclaredField("primaryPublicKey");
        publicKeyField.setAccessible(true);
        LTPAPublicKey actualPublicKey = (LTPAPublicKey) publicKeyField.get(tokenFactory);

        assertEquals("The public key must be equals to the expected public key.", expectedPublicKey, actualPublicKey);
    }

    @Test
    public void testInitializeSetsPrivateKey() throws Exception {
        LTPAPrivateKey expectedPrivateKey = (LTPAPrivateKey) tokenFactoryMap.get("primary_ltpa_private_key");
        Field privateKeyField = LTPAToken2Factory.class.getDeclaredField("primaryPrivateKey");
        privateKeyField.setAccessible(true);
        LTPAPrivateKey actualPrivateKey = (LTPAPrivateKey) privateKeyField.get(tokenFactory);

        assertEquals("The private key must be equals to the expected private key.", expectedPrivateKey, actualPrivateKey);
    }

    @Test
    public void testCreateToken() throws Exception {
        Map<String, Object> tokenData = createBasicLTPA2TokenData();
        Token token = tokenFactory.createToken(tokenData);
        assertNotNull("There must be a token.", token);
    }

    @Test
    public void testCreateTokenThrowsExceptionWhenNoUniqueIdIsProvided() throws Throwable {
        try {
            Map<String, Object> tokenData = new HashMap<String, Object>();
            tokenFactory.createToken(tokenData);
        } catch (TokenCreationFailedException e) {
            String expectedMessage = "CWWKS4101E: There is no unique ID with which to create the token.";
            String actualMessage = e.getMessage();
            assertEquals("Exception did not contain expected message",
                         expectedMessage, actualMessage);
            assertTrue("Expected message was not logged",
                       outputMgr.checkForStandardErr(expectedMessage));
        }
    }

    @Test
    public void testValidateTokenBytes() throws Exception {
        Map<String, Object> tokenData = createBasicLTPA2TokenData();
        Token token = tokenFactory.createToken(tokenData);
        byte[] tokenBytes = token.getBytes();
        Token validatedToken = tokenFactory.validateTokenBytes(tokenBytes);
        assertNotNull("There must be a validated token.", validatedToken);
        assertTrue("Token is invalid.", validatedToken.isValid());
    }

    @Test
    public void testCreateAndValidateAESGMAC256SymmetricToken() throws Exception {
        byte[] sharedKey = "12345678901234567890123456789012".getBytes(); // 32 bytes master key
        Map<String, Object> symmetricFactoryMap = new HashMap<String, Object>();
        symmetricFactoryMap.put("expiration", 120L);
        symmetricFactoryMap.put("primary_ltpa_shared_key", sharedKey);
        symmetricFactoryMap.put("expirationDifferenceAllowed", 0L);
        symmetricFactoryMap.put(LTPAConstants.CONFIGURED_SIGNING_MODE, "symmetric");
        symmetricFactoryMap.put(LTPAConstants.CONFIGURED_SYMMETRIC_SIG_ALG, "AES-GMAC-256");
        symmetricFactoryMap.put(LTPAConstants.CONFIGURED_RESOLVED_CIPHER, "AES/GCM/NoPadding");
        symmetricFactoryMap.put(LTPAConstants.CONFIGURED_RESOLVED_KEY_LENGTH, 32);

        LTPAToken2Factory symmetricFactory = createInitializedTokenFactory(symmetricFactoryMap);

        Map<String, Object> tokenData = createBasicLTPA2TokenData();
        Token token = symmetricFactory.createToken(tokenData);
        assertNotNull("There must be a token.", token);

        byte[] tokenBytes = token.getBytes();
        assertTrue("Token must have header magic", LTPATokenHeader.hasMagic(tokenBytes));
        assertEquals("SigAlg must be AES-GMAC-256 (0x06)", LTPATokenHeader.SIG_ALG_AES_GMAC_256, tokenBytes[5]);
        assertEquals("EncAlg must be AES-GCM-256 (0x03)", LTPATokenHeader.ENC_ALG_AES_GCM_256, tokenBytes[6]);

        Token validatedToken = symmetricFactory.validateTokenBytes(tokenBytes);
        assertNotNull("There must be a validated token.", validatedToken);
        assertTrue("Token must be valid.", validatedToken.isValid());
    }

    @Test
    public void testCreateAndValidateHMACSHA256SymmetricToken() throws Exception {
        byte[] sharedKey = "12345678901234567890123456789012".getBytes(); // 32 bytes master key
        Map<String, Object> symmetricFactoryMap = new HashMap<String, Object>();
        symmetricFactoryMap.put("expiration", 120L);
        symmetricFactoryMap.put("primary_ltpa_shared_key", sharedKey);
        symmetricFactoryMap.put("expirationDifferenceAllowed", 0L);
        symmetricFactoryMap.put(LTPAConstants.CONFIGURED_SIGNING_MODE, "symmetric");
        symmetricFactoryMap.put(LTPAConstants.CONFIGURED_SYMMETRIC_SIG_ALG, "HMAC-SHA-256");
        symmetricFactoryMap.put(LTPAConstants.CONFIGURED_RESOLVED_CIPHER, "AES/GCM/NoPadding");
        symmetricFactoryMap.put(LTPAConstants.CONFIGURED_RESOLVED_KEY_LENGTH, 32);

        LTPAToken2Factory symmetricFactory = createInitializedTokenFactory(symmetricFactoryMap);

        Token token = symmetricFactory.createToken(createBasicLTPA2TokenData());
        assertNotNull("There must be a token.", token);

        byte[] tokenBytes = token.getBytes();
        assertTrue("Token must have header magic", LTPATokenHeader.hasMagic(tokenBytes));
        assertEquals("SigAlg must be HMAC-SHA-256 (0x07)", LTPATokenHeader.SIG_ALG_HMAC_SHA_256, tokenBytes[5]);
        assertEquals("EncAlg must be AES-GCM-256 (0x03)", LTPATokenHeader.ENC_ALG_AES_GCM_256, tokenBytes[6]);

        Token validatedToken = symmetricFactory.validateTokenBytes(tokenBytes);
        assertNotNull("There must be a validated token.", validatedToken);
        assertTrue("Token must be valid.", validatedToken.isValid());
    }

    @Test
    public void testSymmetricSigAlgDefaultsToHMACSHA256() throws Exception {
        byte[] sharedKey = "12345678901234567890123456789012".getBytes(); // 32 bytes master key
        Map<String, Object> symmetricFactoryMap = new HashMap<String, Object>();
        symmetricFactoryMap.put("expiration", 120L);
        symmetricFactoryMap.put("primary_ltpa_shared_key", sharedKey);
        symmetricFactoryMap.put("expirationDifferenceAllowed", 0L);
        symmetricFactoryMap.put(LTPAConstants.CONFIGURED_SIGNING_MODE, "symmetric");
        symmetricFactoryMap.put(LTPAConstants.CONFIGURED_RESOLVED_CIPHER, "AES/GCM/NoPadding");
        symmetricFactoryMap.put(LTPAConstants.CONFIGURED_RESOLVED_KEY_LENGTH, 32);

        LTPAToken2Factory symmetricFactory = createInitializedTokenFactory(symmetricFactoryMap);

        byte[] tokenBytes = symmetricFactory.createToken(createBasicLTPA2TokenData()).getBytes();
        assertEquals("Default symmetric SigAlg must be HMAC-SHA-256 (0x07)", LTPATokenHeader.SIG_ALG_HMAC_SHA_256, tokenBytes[5]);
        assertTrue("Token must be valid.", symmetricFactory.validateTokenBytes(tokenBytes).isValid());
    }

    @Test
    public void testHMACSHA256SigningWithCBC256Encryption() throws Exception {
        byte[] sharedKey = "12345678901234567890123456789012".getBytes(); // 32 bytes master key
        Map<String, Object> symmetricFactoryMap = new HashMap<String, Object>();
        symmetricFactoryMap.put("expiration", 120L);
        symmetricFactoryMap.put("primary_ltpa_shared_key", sharedKey);
        symmetricFactoryMap.put("expirationDifferenceAllowed", 0L);
        symmetricFactoryMap.put(LTPAConstants.CONFIGURED_SIGNING_MODE, "symmetric");
        symmetricFactoryMap.put(LTPAConstants.CONFIGURED_SYMMETRIC_SIG_ALG, "HMAC-SHA-256");
        symmetricFactoryMap.put(LTPAConstants.CONFIGURED_RESOLVED_CIPHER, "AES/CBC/PKCS5Padding");
        symmetricFactoryMap.put(LTPAConstants.CONFIGURED_RESOLVED_KEY_LENGTH, 32); // AES-CBC-256

        LTPAToken2Factory symmetricFactory = createInitializedTokenFactory(symmetricFactoryMap);

        byte[] tokenBytes = symmetricFactory.createToken(createBasicLTPA2TokenData()).getBytes();
        assertEquals("SigAlg must be HMAC-SHA-256 (0x07)", LTPATokenHeader.SIG_ALG_HMAC_SHA_256, tokenBytes[5]);
        assertEquals("EncAlg must be AES-CBC-256 (0x02)", LTPATokenHeader.ENC_ALG_AES_CBC_256, tokenBytes[6]);
        assertTrue("Token must be valid.", symmetricFactory.validateTokenBytes(tokenBytes).isValid());
    }

    @Test
    public void testTokenSignedWithOneSymmetricAlgIsValidatedByHeader() throws Exception {
        byte[] sharedKey = "12345678901234567890123456789012".getBytes(); // 32 bytes master key

        Map<String, Object> hmacMap = new HashMap<String, Object>();
        hmacMap.put("expiration", 120L);
        hmacMap.put("primary_ltpa_shared_key", sharedKey);
        hmacMap.put("expirationDifferenceAllowed", 0L);
        hmacMap.put(LTPAConstants.CONFIGURED_SIGNING_MODE, "symmetric");
        hmacMap.put(LTPAConstants.CONFIGURED_SYMMETRIC_SIG_ALG, "HMAC-SHA-256");
        hmacMap.put(LTPAConstants.CONFIGURED_RESOLVED_CIPHER, "AES/GCM/NoPadding");
        hmacMap.put(LTPAConstants.CONFIGURED_RESOLVED_KEY_LENGTH, 32);
        LTPAToken2Factory hmacFactory = createInitializedTokenFactory(hmacMap);

        Map<String, Object> gmacMap = new HashMap<String, Object>(hmacMap);
        gmacMap.put(LTPAConstants.CONFIGURED_SYMMETRIC_SIG_ALG, "AES-GMAC-256");
        LTPAToken2Factory gmacFactory = createInitializedTokenFactory(gmacMap);

        // The header, not the local config, decides which algorithm verifies the token.
        byte[] hmacTokenBytes = hmacFactory.createToken(createBasicLTPA2TokenData()).getBytes();
        byte[] gmacTokenBytes = gmacFactory.createToken(createBasicLTPA2TokenData()).getBytes();
        assertTrue("GMAC-configured factory must validate an HMAC token", gmacFactory.validateTokenBytes(hmacTokenBytes).isValid());
        assertTrue("HMAC-configured factory must validate a GMAC token", hmacFactory.validateTokenBytes(gmacTokenBytes).isValid());
    }

    @Test
    public void testCreateAndValidateAESGMAC256SigningWithCBCEncryption() throws Exception {
        byte[] sharedKey = "12345678901234567890123456789012".getBytes(); // 32 bytes master key
        Map<String, Object> symmetricFactoryMap = new HashMap<String, Object>();
        symmetricFactoryMap.put("expiration", 120L);
        symmetricFactoryMap.put("primary_ltpa_shared_key", sharedKey);
        symmetricFactoryMap.put("expirationDifferenceAllowed", 0L);
        symmetricFactoryMap.put(LTPAConstants.CONFIGURED_SIGNING_MODE, "symmetric");
        symmetricFactoryMap.put(LTPAConstants.CONFIGURED_SYMMETRIC_SIG_ALG, "AES-GMAC-256");
        symmetricFactoryMap.put(LTPAConstants.CONFIGURED_RESOLVED_CIPHER, "AES/CBC/PKCS5Padding");
        symmetricFactoryMap.put(LTPAConstants.CONFIGURED_RESOLVED_KEY_LENGTH, 16); // AES-CBC-128

        LTPAToken2Factory symmetricFactory = createInitializedTokenFactory(symmetricFactoryMap);

        Map<String, Object> tokenData = createBasicLTPA2TokenData();
        Token token = symmetricFactory.createToken(tokenData);
        assertNotNull("There must be a token.", token);

        byte[] tokenBytes = token.getBytes();
        assertTrue("Token must have header magic", LTPATokenHeader.hasMagic(tokenBytes));
        assertEquals("SigAlg must be AES-GMAC-256 (0x06)", LTPATokenHeader.SIG_ALG_AES_GMAC_256, tokenBytes[5]);
        assertEquals("EncAlg must be AES-CBC-128 (0x01)", LTPATokenHeader.ENC_ALG_AES_CBC_128, tokenBytes[6]);

        Token validatedToken = symmetricFactory.validateTokenBytes(tokenBytes);
        assertNotNull("There must be a validated token.", validatedToken);
        assertTrue("Token must be valid.", validatedToken.isValid());
    }

    @Test
    public void testCreateAndValidateAESGMAC256SigningWithCBC256Encryption() throws Exception {
        byte[] sharedKey = "12345678901234567890123456789012".getBytes(); // 32 bytes master key
        Map<String, Object> symmetricFactoryMap = new HashMap<String, Object>();
        symmetricFactoryMap.put("expiration", 120L);
        symmetricFactoryMap.put("primary_ltpa_shared_key", sharedKey);
        symmetricFactoryMap.put("expirationDifferenceAllowed", 0L);
        symmetricFactoryMap.put(LTPAConstants.CONFIGURED_SIGNING_MODE, "symmetric");
        symmetricFactoryMap.put(LTPAConstants.CONFIGURED_SYMMETRIC_SIG_ALG, "AES-GMAC-256");
        symmetricFactoryMap.put(LTPAConstants.CONFIGURED_RESOLVED_CIPHER, "AES/CBC/PKCS5Padding");
        symmetricFactoryMap.put(LTPAConstants.CONFIGURED_RESOLVED_KEY_LENGTH, 32); // AES-CBC-256

        LTPAToken2Factory symmetricFactory = createInitializedTokenFactory(symmetricFactoryMap);

        Map<String, Object> tokenData = createBasicLTPA2TokenData();
        Token token = symmetricFactory.createToken(tokenData);
        assertNotNull("There must be a token.", token);

        byte[] tokenBytes = token.getBytes();
        assertTrue("Token must have header magic", LTPATokenHeader.hasMagic(tokenBytes));
        assertEquals("SigAlg must be AES-GMAC-256 (0x06)", LTPATokenHeader.SIG_ALG_AES_GMAC_256, tokenBytes[5]);
        assertEquals("EncAlg must be AES-CBC-256 (0x02)", LTPATokenHeader.ENC_ALG_AES_CBC_256, tokenBytes[6]);

        Token validatedToken = symmetricFactory.validateTokenBytes(tokenBytes);
        assertNotNull("There must be a validated token.", validatedToken);
        assertTrue("Token must be valid.", validatedToken.isValid());
    }

    @Test
    public void testCanonicalAlgorithmHeaderDecoding() throws Exception {
        assertEquals("AES-GCM-256", LTPATokenHeader.decodeCanonicalEncAlg(LTPATokenHeader.ENC_ALG_AES_GCM_256));
        assertEquals("AES-CBC-128", LTPATokenHeader.decodeCanonicalEncAlg(LTPATokenHeader.ENC_ALG_AES_CBC_128));
        assertEquals("AES-CBC-256", LTPATokenHeader.decodeCanonicalEncAlg(LTPATokenHeader.ENC_ALG_AES_CBC_256));
        assertEquals("KDF", LTPATokenHeader.decodeCanonicalEncAlg(LTPATokenHeader.ENC_ALG_KDF_AES_GCM_256));
        assertNull(LTPATokenHeader.decodeCanonicalEncAlg(LTPATokenHeader.ENC_ALG_NONE));

        assertEquals("AES-GCM-256", LTPATokenHeader.toCanonicalEncAlg("AES/GCM/NoPadding", 32));
        assertEquals("AES-CBC-128", LTPATokenHeader.toCanonicalEncAlg("AES/CBC/PKCS5Padding", 16));
        assertEquals("AES-CBC-256", LTPATokenHeader.toCanonicalEncAlg("AES/CBC/PKCS5Padding", 32));
    }

    private Map<String, Object> createBasicLTPA2TokenData() {
        Map<String, Object> tokenData = new HashMap<String, Object>();
        tokenData.put("unique_id", "user:BasicRealm/u\\ser |1$");
        return tokenData;
    }
}
