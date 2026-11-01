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
package com.ibm.ws.security.token.ltpa;

import java.io.IOException;
import java.io.InputStream;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.crypto.BadPaddingException;

import com.ibm.websphere.crypto.PasswordUtil;
import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Sensitive;
import com.ibm.ws.common.crypto.CryptoUtils;
import com.ibm.ws.common.encoder.Base64Coder;
import com.ibm.ws.crypto.ltpakeyutil.KeyEncryptor;
import com.ibm.ws.crypto.ltpakeyutil.LTPAKeyFileUtility;
import com.ibm.ws.ffdc.annotation.FFDCIgnore;
import com.ibm.ws.security.token.ltpa.internal.LTPAKeyFileCreator;
import com.ibm.ws.security.token.ltpa.internal.LTPAKeyFileCreatorImpl;
import com.ibm.wsspi.kernel.service.location.WsLocationAdmin;
import com.ibm.wsspi.kernel.service.location.WsResource;
import com.ibm.wsspi.kernel.service.utils.TimestampUtils;

/**
 * Load or create an LTPA keys file, something that looks like this:
 *
 * <pre>
 * #IBM WebSphere Application Server key file
 * #Tue Sep 11 16:15:40 EDT 2007
 * com.ibm.websphere.CreationDate=Tue Sep 11 16\:15\:40 EDT 2007
 * com.ibm.websphere.ltpa.version=1.0
 * com.ibm.websphere.CreationHost=localhost
 * com.ibm.websphere.ltpa.Realm=SecureRealm
 *
 *
 * com.ibm.websphere.ltpa.3DESKey=YJ8ARFn0k2S5S5LONNdZG/mLvfYxa4gH3/cGjIn+mR4\=
 * com.ibm.websphere.ltpa.PrivateKey=vzJcMLGvZqZqbrCGF7zTHAmXAhaZpuZ1XGT0iRq+9Y7VY29/UoIeJkunVyWUSmGrlfqD8kLc5jWUKBMynpg3tQqYKEls5iaO8DtI5FiGWE79gDUYzIkMjGei6S23KqE62Rq+
 * BcrjJv9XYcoGJhLvnE9wftBRrNeI6WPO44KywBSH0sgilyqOvxF87YumiCazbFsbCuBBlDh0daVvosM6zCfQGEsP
 * /e2AQRg4N6kkLbswaeE+i8AoNs2eIGpuicAx5avCgeBT8WwYUhkl3qDaYlR8/kHXOIOPt7/6oW//8yPpvWcHaxEdW4rZrdjH3TEh7CyVN6u6fS7CiOwgodJXrXPpLajqr6nFZxMSwMSyEcQ\=
 * com.ibm.websphere.ltpa.PublicKey=ANKHjHZGY0Ry2jG6kWAOOdGFr8IDhP3igXAAtKNRjhz1SuHcgLq0ZF+mA50pfRBFuFWGxa8WEPthfMyx/xEncHMcoakGXJH1woLL3Bp+LYd/
 * HlYYOHnLtmcWYQOPseqn638nkRWVpVsayIWx9jonjFJx+vbsi5ah3volxurVWZe/AQAB
 * <p>
 * com.ibm.websphere.ltpa.3DESKey_1=YJ8ARFn0k2S5S5LONNdZG/mLvfYxa4gH3/cGjIn+mR4\=
 * com.ibm.websphere.ltpa.PrivateKey_1=vzJcMLGvZqZqbrCGF7zTHAmXAhaZpuZ1XGT0iRq+9Y7VY29/UoIeJkunVyWUSmGrlfqD8kLc5jWUKBMynpg3tQqYKEls5iaO8DtI5FiGWE79gDUYzIkMjGei6S23KqE62Rq+
 * BcrjJv9XYcoGJhLvnE9wftBRrNeI6WPO44KywBSH0sgilyqOvxF87YumiCazbFsbCuBBlDh0daVvosM6zCfQGEsP
 * /e2AQRg4N6kkLbswaeE+i8AoNs2eIGpuicAx5avCgeBT8WwYUhkl3qDaYlR8/kHXOIOPt7/6oW//8yPpvWcHaxEdW4rZrdjH3TEh7CyVN6u6fS7CiOwgodJXrXPpLajqr6nFZxMSwMSyEcQ\=
 * com.ibm.websphere.ltpa.PublicKey_1=ANKHjHZGY0Ry2jG6kWAOOdGFr8IDhP3igXAAtKNRjhz1SuHcgLq0ZF+mA50pfRBFuFWGxa8WEPthfMyx/xEncHMcoakGXJH1woLL3Bp+LYd/
 * HlYYOHnLtmcWYQOPseqn638nkRWVpVsayIWx9jonjFJx+vbsi5ah3volxurVWZe/AQAB
 * </p>
 * </pre>
 *
 * Note:
 * key version start with 0 or no index. For example 3DESKey or 3DESKey_0
 * (key verion 0 is blank or 0)
 *
 * com.ibm.websphere.ltpa.version=1.0 - No FIPS
 * com.ibm.websphere.ltpa.version=2.0 - FIPS
 */
public class LTPAKeyInfoManager {

    private static final TraceComponent tc = Tr.register(LTPAKeyInfoManager.class);

    private static final String SECRETKEY = "secretkey";
    private static final String PRIVATEKEY = "privatekey";
    private static final String PUBLICKEY = "publickey";
    // PQC key cache identifiers (Issue #35556 - Task 2.3)
    private static final String MLDSA_PRIVATEKEY = "mldsaprivatekey";
    private static final String MLDSA_PUBLICKEY = "mldsapublickey";
    private static final String LTPA_KEYS_BACKUP_EXTENSION = ".defaultpassword.backup";

    private static final int MLDSA_44_65_THRESHOLD  = 1700; // 1312..1700 → ML-DSA-44
    private static final int MLDSA_65_87_THRESHOLD  = 2300; // 1701..2300 → ML-DSA-65

    private final List<String> importFileCache = new ArrayList<String>();
    private final Map<String, byte[]> keyCache = new Hashtable<String, byte[]>();
    private final Map<String, String> realmCache = new Hashtable<String, String>();
    private final String suffixNoFips = ".nofips";
    private final String suffixFips = ".fips";
    private final String suffixPqc = ".pqc";

    private static CopyOnWriteArrayList<LTPAValidationKeysInfo> ltpaValidationKeysInfos = new CopyOnWriteArrayList<LTPAValidationKeysInfo>();

    /**
     * Load the contents of the properties file.
     *
     * @param res The WsResource of the key import file.
     *
     * @return The properties
     * @throws TokenException
     */
    private final Properties loadPropertiesFile(WsResource res) throws IOException {

        Properties props = new Properties();
        InputStream is = res.get();
        try {
            props.load(is);
        } catch (IOException e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                Tr.event(this, tc, "Error loading properties; " + e);
            }
            throw e;
        } finally {
            if (is != null)
                try {
                    is.close();
                } catch (IOException e) {
                }
        }
        return props;
    }

    /**
     * Loads the contents of the primary/validation LTPA key import file if necessary.
     *
     * @param primaryKeyImportFile The URL of the key import file. If it's not the URL, it is assumed as a relative path from
     *                                 ${app.root}/config
     * @param primaryKeyPassword   The password of the LTPA keys
     * @param validationKeys       The validationKeys
     * @throws IOException
     */
    @SuppressWarnings("deprecation")
    public synchronized final void prepareLTPAKeyInfo(WsLocationAdmin locService, String primaryKeyImportFile, @Sensitive byte[] primaryKeyPassword,
                                                      @Sensitive List<Properties> validationKeys, boolean tryToReEncryptLtpaKeys, String signingMode, String mldsaAlgorithm, int classicalKeySize) throws Exception {
        if (!this.importFileCache.contains(primaryKeyImportFile)) {
            loadLtpaKeysFile(locService, primaryKeyImportFile, primaryKeyPassword, false, false, null, tryToReEncryptLtpaKeys, signingMode, mldsaAlgorithm, classicalKeySize);
        }
        if (validationKeys != null && !validationKeys.isEmpty()) {
            ltpaValidationKeysInfos.clear();
            //load validationKeys
            Iterator<Properties> validationKeysIterator = validationKeys.iterator();
            while (validationKeysIterator.hasNext()) {
                OffsetDateTime validUntilDateOdt = null;
                Properties vKeys = validationKeysIterator.next();
                String filename = (String) vKeys.get(LTPAConfiguration.CFG_KEY_VALIDATION_FILE_NAME);
                if (!this.importFileCache.contains(vKeys.get(LTPAConfiguration.CFG_KEY_VALIDATION_FILE_NAME))) {
                    String validUntilDate = ((String) vKeys.get(LTPAConfiguration.CFG_KEY_VALIDATION_VALID_UNTIL_DATE));
                    if (validUntilDate != null) {
                        try {
                            validUntilDateOdt = OffsetDateTime.parse(validUntilDate);
                            if (validUntilDateOdt != null && isValidUntilDateExpired(filename, validUntilDateOdt)) {
                                continue; //Skip this LTPA validationKeys
                            }
                        } catch (Exception e) {
                            Tr.error(tc, "LTPA_VALIDATION_KEYS_VALID_UNTIL_DATE_INVALID_FORMAT", validUntilDate, filename);
                            continue; //Skip this LTPA validationKeys
                        }
                    }

                    byte[] password = getKeyPasswordBytes(vKeys);
                    boolean isConfiguredValidationKey = Boolean.valueOf(vKeys.getProperty(LTPAConfiguration.INTERNAL_KEY_IS_CONFIGURED_VALIDATION_KEY));
                    loadLtpaKeysFile(locService, filename, password, true, isConfiguredValidationKey, validUntilDateOdt, tryToReEncryptLtpaKeys, signingMode, mldsaAlgorithm, classicalKeySize);
                }
            }
        }

        if (tc.isDebugEnabled()) {
            Tr.debug(this, tc, "importFileCache: " + importFileCache.toString());
            Tr.debug(this, tc, "keyCache: " + keyCache.toString());
            Tr.debug(this, tc, "realmCache: " + realmCache.toString());
            Tr.debug(this, tc, "number of ltpaValidationKeysInfos: " + ltpaValidationKeysInfos.size());
        }
    }

    /**
     * This function checks if the validUntilDate0dt has already passed the current time.
     * If so, then they key is expired, and will return true with a warning message.
     * Otherwise, the key is valid and will return false.
     * If the validUntilDateOdt is null, then the key is forever valid and will return false.
     *
     * @param filename
     * @param validUntilDateOdt
     *
     * @return
     */
    public boolean isValidUntilDateExpired(String filename, OffsetDateTime validUntilDateOdt) {
        OffsetDateTime currentTime = OffsetDateTime.now(validUntilDateOdt.getOffset());

        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "current date: " + currentTime);
        }

        if (validUntilDateOdt.isBefore(currentTime)) {
            Tr.warning(tc, "LTPA_VALIDATION_KEYS_VALID_UNTIL_DATE_IS_IN_THE_PAST", validUntilDateOdt, filename);
            return true;
        } else {
            return false;
        }
    }

    @Sensitive
    byte[] getKeyPasswordBytes(@Sensitive Properties vKeys) {
        String password = (String) vKeys.get(LTPAConfiguration.CFG_KEY_VALIDATION_PASSWORD);
        return PasswordUtil.passwordDecode(password).getBytes();
    }

    /**
     * @param locService
     * @param keyImportFile
     * @param keyPassword
     * @param validationKey
     * @param validUntilDateOdt
     * @throws IOException
     * @throws Exception
     */
    private void loadLtpaKeysFile(WsLocationAdmin locService, String keyImportFile, @Sensitive byte[] keyPassword, boolean validationKey, boolean isConfiguredValidationKey,
                                  OffsetDateTime validUntilDateOdt, boolean tryToReEncryptLtpaKeys, String signingMode, String mldsaAlgorithm, int classicalKeySize) throws IOException, Exception {
        // Need to load the key import file
        if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
            Tr.event(this, tc, "Loading LTPA " + (validationKey == true ? "validation" : "primary") + "Keys file: " + keyImportFile);
        }
        Properties props = null;
        //Check to see if the LTPA key import file exists, create the keys and file if not
        WsResource ltpaKeyFileResource = getLTPAKeyFileResource(locService, keyImportFile);

        if (ltpaKeyFileResource != null) {
            props = loadPropertiesFile(ltpaKeyFileResource);
            String version = props.getProperty(LTPAKeyFileUtility.LTPA_VERSION_PROPERTY);
            if (tc.isDebugEnabled()) {
                Tr.debug(this, tc, "LTPA key version: " + version);
            }

            boolean isPqcMode = "pqc".equals(signingMode);
            boolean isFips = CryptoUtils.isFips140_3Enabled();

            if (!validationKey) {
                // Determine whether the primary key file version is compatible with the resolved
                // configuration (PQC mode vs. classical RSA key size).
                boolean versionMismatch = false;
                String restoreSuffix = null;

                if (isPqcMode) {
                    if (!"3.0".equals(version)) {
                        versionMismatch = true;
                        restoreSuffix = suffixPqc;
                    }
                } else {
                    // Classical mode configured
                    if ("3.0".equals(version)) {
                        // Classical mode configured, but file is v3.0 (ML-DSA-only).
                        // Back up with .pqc, restore from the suffix that matches the configured RSA key size:
                        //   RSA-2048 (classicalKeySize >= 256) → .fips  (where v2.0 backups are stored)
                        //   RSA-1024 (classicalKeySize <  256) → .nofips (where v1.0 backups are stored)
                        versionMismatch = true;
                        restoreSuffix = (classicalKeySize >= 256) ? suffixFips : suffixNoFips;
                    } else if (classicalKeySize >= 256 && "1.0".equals(version)) {
                        // RSA-2048 configured, but file is v1.0 (RSA-1024).
                        // Back up with .nofips, restore .fips backup if available, else regenerate to v2.0.
                        versionMismatch = true;
                        restoreSuffix = suffixFips;
                    } else if (classicalKeySize < 256 && "2.0".equals(version)) {
                        // RSA-1024 configured, but file is v2.0 (RSA-2048).
                        // Back up with .fips, restore .nofips backup if available, else regenerate to v1.0.
                        versionMismatch = true;
                        restoreSuffix = suffixNoFips;
                    }
                }

                if (versionMismatch) {
                    backupLtpaKeyFile(locService, keyImportFile, ltpaKeyFileResource, version);
                    if (restoreLtpaKeyFile(locService, keyImportFile, ltpaKeyFileResource, restoreSuffix)) {
                        props = loadPropertiesFile(ltpaKeyFileResource);
                    } else {
                        props = createPrimaryKeyFile(locService, keyImportFile, keyPassword, signingMode, mldsaAlgorithm, classicalKeySize);
                    }
                } else {
                    // ---------------------------------------------------------------
                    // Configuration-mismatch detection: version is compatible with the
                    // current mode, but the stored key sizes do not match the server
                    // configuration.  No backup is taken; keys are regenerated in-place.
                    // ---------------------------------------------------------------
                    if (isRsaKeySizeMismatch(props, classicalKeySize)) {
                        if (tc.isDebugEnabled()) {
                            Tr.debug(this, tc, "RSA key size mismatch for " + keyImportFile + "; regenerating.");
                        }
                        props = createPrimaryKeyFile(locService, keyImportFile, keyPassword, signingMode, mldsaAlgorithm, classicalKeySize);
                    } else if (isMldsaKeySizeMismatch(props, mldsaAlgorithm)) {
                        if (tc.isDebugEnabled()) {
                            Tr.debug(this, tc, "ML-DSA key size mismatch for " + keyImportFile + "; regenerating.");
                        }
                        props = createPrimaryKeyFile(locService, keyImportFile, keyPassword, signingMode, mldsaAlgorithm, classicalKeySize);
                    }
                }
            } else {
                // validationKey == true: Validation keys are used to validate tokens of all types.
                // Only reject v1.0 keys if FIPS 140-3 mode is strictly enabled.
                if (isFips && "1.0".equals(version)) {
                    Tr.warning(tc, "LTPA_VALIDATION_KEYS_NEED_TO_REGENERATE", keyImportFile);
                    return;
                }
            }

        } else if (validationKey) { //validationKeys file does not exist so error
            Tr.error(tc, "LTPA_KEYS_FILE_DOES_NOT_EXIST", keyImportFile);
            return;
        } else { //Primary keys file does not exist so create the primary key
            props = createPrimaryKeyFile(locService, keyImportFile, keyPassword, signingMode, mldsaAlgorithm, classicalKeySize);
        }

        if (props == null || props.isEmpty()) {
            return;
        }
        String realm = props.getProperty(LTPAKeyFileUtility.KEYIMPORT_REALM);
        String version = props.getProperty(LTPAKeyFileUtility.LTPA_VERSION_PROPERTY);
        // Try both property names: v1.0/v3.0 files use 3DESKey, v2.0 files use SharedKey
        String secretKeyStr = props.getProperty(LTPAKeyFileUtility.KEYIMPORT_SECRETKEY_V1);
        if (secretKeyStr == null || secretKeyStr.isEmpty()) {
            secretKeyStr = props.getProperty(LTPAKeyFileUtility.KEYIMPORT_SECRETKEY_V2);
        }
        String privateKeyStr = props.getProperty(LTPAKeyFileUtility.KEYIMPORT_PRIVATEKEY);
        String publicKeyStr = props.getProperty(LTPAKeyFileUtility.KEYIMPORT_PUBLICKEY);
        String mldsaPrivateKeyStr = props.getProperty(LTPAKeyFileUtility.KEYIMPORT_MLDSA_PRIVATEKEY);
        String mldsaPublicKeyStr = props.getProperty(LTPAKeyFileUtility.KEYIMPORT_MLDSA_PUBLICKEY);

        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "PQC keys present: " + (mldsaPrivateKeyStr != null && mldsaPublicKeyStr != null));
        }

        // v2.0 and v3.0 key files are always encrypted with AES regardless of the
        // writing server's FIPS mode, so any server can load them.
        boolean useAES = "2.0".equals(version) || "3.0".equals(version);

        byte[] secretKey, privateKey, publicKey;
        byte[] mldsaPrivateKey, mldsaPublicKey;
        byte[][] keys;

        try {
            keys = decryptKeys(keyPassword, secretKeyStr, privateKeyStr, publicKeyStr, mldsaPrivateKeyStr, mldsaPublicKeyStr, useAES);
        } catch (BadPaddingException e) {
            // only try to re-encrypt if it failed with keystore_password and it's not a configured validationKeys
            if (!tryToReEncryptLtpaKeys || (validationKey && isConfiguredValidationKey)) {
                if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                    Tr.event(this, tc, "Error loading key; " + e);
                }
                throw e;
            }

            keys = reEncryptLtpaKey(locService, "WebAS".getBytes(), keyPassword,
                                    secretKeyStr, privateKeyStr, publicKeyStr,
                                    keyImportFile, ltpaKeyFileResource, e, useAES);
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                Tr.event(this, tc, "Error loading key; " + e);
            }
            throw e;
        }

        secretKey = keys[0];
        if (secretKey != null) {
            this.keyCache.put(keyImportFile + SECRETKEY, secretKey);
        }
        privateKey = keys[1];
        if (privateKey != null) {
            this.keyCache.put(keyImportFile + PRIVATEKEY, privateKey);
        }
        publicKey = keys[2];
        if (publicKey != null) {
            this.keyCache.put(keyImportFile + PUBLICKEY, publicKey);
        }
        mldsaPrivateKey = keys[3];
        if (mldsaPrivateKey != null) {
            this.keyCache.put(keyImportFile + MLDSA_PRIVATEKEY, mldsaPrivateKey);
        }
        mldsaPublicKey = keys[4];
        if (mldsaPublicKey != null) {
            this.keyCache.put(keyImportFile + MLDSA_PUBLICKEY, mldsaPublicKey);
        }

        if (realm != null) {
            this.realmCache.put(keyImportFile, realm);
        }

        this.importFileCache.add(keyImportFile);

        if (validationKey) {
            LTPAValidationKeysInfo info;
            if (mldsaPublicKey != null) {
                info = new LTPAValidationKeysInfo(keyImportFile, secretKey, mldsaPrivateKey, mldsaPublicKey, validUntilDateOdt, true);
            } else {
                info = new LTPAValidationKeysInfo(keyImportFile, secretKey, privateKey, publicKey, validUntilDateOdt);
            }
            ltpaValidationKeysInfos.add(info);
            if (tc.isDebugEnabled()) {
                Tr.debug(this, tc, "ValidationKeys: " + keyImportFile + " validUntilDate: " + validUntilDateOdt);
                Tr.debug(this, tc, "LTPAValidationKeysInfo size: " + ltpaValidationKeysInfos.size());
            }
        }
    }

    @Sensitive
    private byte[][] decryptKeys(@Sensitive byte[] keyPassword, @Sensitive String secretKeyStr, @Sensitive String privateKeyStr,
                                 @Sensitive String publicKeyStr, @Sensitive String mldsaPrivateKeyStr,
                                 @Sensitive String mldsaPublicKeyStr, boolean useAES) throws Exception {
        long startDecryptKeys = System.currentTimeMillis();
        // Key decrypting algorithm mirrors key encrypting algorithm used at write time
        String keyEncAlgorithm = useAES ? "AES-CBC-256" : CryptoUtils.getCipher();
        System.out.println("[LTPAKeyInfoManager] decryptKeys: start; keyEncAlgorithm=" + keyEncAlgorithm
                + ", hasMldsaKeys=" + (mldsaPrivateKeyStr != null) + "; time=" + startDecryptKeys + " ms");

        // KeyEncryptor construction (password-based key derivation via SHA-256)
        long startEncryptor = System.currentTimeMillis();
        KeyEncryptor encryptor = new KeyEncryptor(keyPassword);
        long encryptorMs = System.currentTimeMillis() - startEncryptor;
        System.out.println("[LTPAKeyInfoManager] decryptKeys: KeyEncryptor construction (SHA-256 digest) took " + encryptorMs + " ms");

        byte[] secretKey, privateKey = null, publicKey = null;
        byte[] mldsaPrivateKey = null, mldsaPublicKey = null;

        // Shared secret key — always required for token payload encryption in all modes.
        if ((secretKeyStr == null) || (secretKeyStr.length() == 0)) {
            Tr.error(tc, "LTPA_TOKEN_SERVICE_MISSING_KEY", LTPAKeyFileUtility.KEYIMPORT_SECRETKEY);
            String formattedMessage = Tr.formatMessage(tc, "LTPA_TOKEN_SERVICE_MISSING_KEY", LTPAKeyFileUtility.KEYIMPORT_SECRETKEY);
            throw new IllegalArgumentException(formattedMessage);
        }
        long startSecretKey = System.currentTimeMillis();
        secretKey = useAES ? encryptor.decryptAES(Base64Coder.base64DecodeString(secretKeyStr))
                           : encryptor.decrypt(Base64Coder.base64DecodeString(secretKeyStr));
        long secretKeyMs = System.currentTimeMillis() - startSecretKey;
        System.out.println("[LTPAKeyInfoManager] decryptKeys: shared secret key (Base64 decode + decrypt, keyEncAlgorithm=" + keyEncAlgorithm + ") took " + secretKeyMs + " ms");

        // RSA keys — present in classical mode, absent in PQC mode.
        if (privateKeyStr != null && privateKeyStr.length() > 0) {
            long startPrivateKey = System.currentTimeMillis();
            privateKey = useAES ? encryptor.decryptAES(Base64Coder.base64DecodeString(privateKeyStr))
                                : encryptor.decrypt(Base64Coder.base64DecodeString(privateKeyStr));
            long privateKeyMs = System.currentTimeMillis() - startPrivateKey;
            System.out.println("[LTPAKeyInfoManager] decryptKeys: RSA private key (Base64 decode + decrypt, keyEncAlgorithm=" + keyEncAlgorithm + ") took " + privateKeyMs + " ms");
        }
        if (publicKeyStr != null && publicKeyStr.length() > 0) {
            long startPublicKey = System.currentTimeMillis();
            publicKey = Base64Coder.base64DecodeString(publicKeyStr);
            long publicKeyMs = System.currentTimeMillis() - startPublicKey;
            System.out.println("[LTPAKeyInfoManager] decryptKeys: RSA public key (Base64 decode only) took " + publicKeyMs + " ms");
        }

        // ML-DSA keys — present in PQC mode, absent in classical mode.
        if (mldsaPrivateKeyStr != null && mldsaPrivateKeyStr.length() > 0) {
            long startMLDSAPrivate = System.currentTimeMillis();
            mldsaPrivateKey = useAES ? encryptor.decryptAES(Base64Coder.base64DecodeString(mldsaPrivateKeyStr))
                                     : encryptor.decrypt(Base64Coder.base64DecodeString(mldsaPrivateKeyStr));
            long mldsaPrivateMs = System.currentTimeMillis() - startMLDSAPrivate;
            System.out.println("[LTPAKeyInfoManager] decryptKeys: ML-DSA private key (Base64 decode + decrypt, keyEncAlgorithm=" + keyEncAlgorithm + ") took " + mldsaPrivateMs + " ms");
        }
        if (mldsaPublicKeyStr != null && mldsaPublicKeyStr.length() > 0) {
            long startMLDSAPublic = System.currentTimeMillis();
            mldsaPublicKey = Base64Coder.base64DecodeString(mldsaPublicKeyStr);
            long mldsaPublicMs = System.currentTimeMillis() - startMLDSAPublic;
            System.out.println("[LTPAKeyInfoManager] decryptKeys: ML-DSA public key (Base64 decode only) took " + mldsaPublicMs + " ms");
        }

        long totalMs = System.currentTimeMillis() - startDecryptKeys;
        System.out.println("[LTPAKeyInfoManager] decryptKeys: end; keyEncAlgorithm=" + keyEncAlgorithm
                + ", encryptor=" + encryptorMs + " ms, total=" + totalMs + " ms");
        return new byte[][] { secretKey, privateKey, publicKey, mldsaPrivateKey, mldsaPublicKey };
    }

    @Sensitive
    private byte[][] reEncryptLtpaKey(WsLocationAdmin locService, @Sensitive byte[] keyPasswordToTry, @Sensitive byte[] keyPasswordToReEncryptWith,
                                      @Sensitive String secretKeyStr, @Sensitive String privateKeyStr, @Sensitive String publicKeyStr,
                                      String keyImportFile, WsResource ltpaKeyFileResource, Exception originalException, boolean useAES) throws Exception {
        try {
            // failed with keystore_password... let's try again with the legacy default password
            byte[][] keys = decryptKeys(keyPasswordToTry, secretKeyStr, privateKeyStr, publicKeyStr, null, null, useAES);

            // successfully decrypted keys; backup and re-encrypt the keys using keystore_password
            Tr.info(tc, "LTPA_KEYS_REENCRYPT", keyImportFile);
            backupLtpaKeys(locService, ltpaKeyFileResource, keyImportFile);
            LTPAKeyFileCreator creator = new LTPAKeyFileCreatorImpl();
            creator.createLTPAKeysFile(locService, keyImportFile, keyPasswordToReEncryptWith, keys[0], keys[1], keys[2]);
            Tr.info(tc, "LTPA_KEYS_REENCRYPT_SUCCESS", keyImportFile);
            return keys;
        } catch (IOException e) {
            Tr.error(tc, "LTPA_KEYS_REENCRYPT_ERROR", keyImportFile, e.getMessage());
            String message = Tr.formatMessage(tc, "LTPA_KEYS_REENCRYPT_ERROR", keyImportFile, e.getMessage());
            throw new IOException(message);
        } catch (Exception e) {
            // didn't work with legacy default password; throw the original exception
            if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                Tr.event(this, tc, "Error loading key (retry): " + e + " Throwing original exception: " + originalException);
            }
            throw originalException;
        }
    }

    /**
     * Try to backup the ltpa.keys to ltpa.keys.defaultpassword.backup
     * If it's not available, then try ltpa.keys.defaultpassword.backup-1 til ltpa.keys.defaultpassword.backup-99
     * If none of those are available (extremely unlikely) then don't back up
     *
     * @param locService
     * @param ltpaKeyFileResource
     * @param keyImportFile
     * @throws IOException
     */
    @FFDCIgnore(Throwable.class)
    private void backupLtpaKeys(WsLocationAdmin locService, WsResource ltpaKeyFileResource, String keyImportFile) throws IOException {
        for (int i = 0; i < 100; i++) {
            String ltpaFileBackupLocation = keyImportFile + LTPA_KEYS_BACKUP_EXTENSION;
            if (i > 0) {
                ltpaFileBackupLocation += ("-" + i);
            }
            WsResource ltpaFileBackup = locService.resolveResource(ltpaFileBackupLocation);
            if (ltpaFileBackup.exists()) {
                continue;
            }
            if (tc.isDebugEnabled()) {
                Tr.debug(this, tc, "Backup the LTPA key file: " + keyImportFile + " to: " + ltpaFileBackupLocation);
            }
            try (InputStream in = ltpaKeyFileResource.get()) {
                ltpaFileBackup.put(in);
            }
            return;
        }
        if (tc.isDebugEnabled()) {
            Tr.debug(this, tc, "Could not find available location to backup the LTPA key file: " + keyImportFile);
        }
    }

    /**
     * @param locService
     * @param keyImportFile
     * @param ltpaKeyFileResource
     * @param version
     * @return
     * @throws IOException
     */
    private void backupLtpaKeyFile(WsLocationAdmin locService, String keyImportFile, WsResource ltpaKeyFileResource, String version) throws IOException {
        String suffix;
        if ("3.0".equals(version)) {
            suffix = suffixPqc;
        } else if ("2.0".equals(version)) {
            suffix = suffixFips;
        } else {
            suffix = suffixNoFips;
        }
        WsResource ltpaFileBackup = locService.resolveResource(keyImportFile + suffix);

        if (ltpaFileBackup.exists()) {
            ltpaFileBackup.delete();
        }

        if (tc.isDebugEnabled()) {
            Tr.debug(this, tc, "Backup the LTPA key file: " + keyImportFile + suffix);
        }
        ltpaKeyFileResource.moveTo(ltpaFileBackup);
    }

    /**
     * @param locService
     * @param keyImportFile
     * @param ltpaKeyFileResource
     * @param suffix
     * @return
     * @throws IOException
     */
    private boolean restoreLtpaKeyFile(WsLocationAdmin locService, String keyImportFile, WsResource ltpaKeyFileResource, String suffix) throws IOException {
        WsResource ltpaFileBackup = locService.resolveResource(keyImportFile + suffix);
        if (ltpaFileBackup.exists()) {
            if (tc.isDebugEnabled()) {
                Tr.debug(this, tc, "Restoring the LTPA key file backup: " + keyImportFile + suffix);
            }
            ltpaFileBackup.moveTo(ltpaKeyFileResource);
            return true;
        }

        return false;
    }

    /**
     * @param props            loaded key file properties
     * @param classicalKeySize configured RSA key size in bytes (128 for 1024-bit, 256 for 2048-bit)
     * @return {@code true} if the stored key does not match the configuration
     */
    private boolean isRsaKeySizeMismatch(Properties props, int classicalKeySize) {
        if (classicalKeySize <= 0) {
            return false;
        }
        String publicKeyStr = props.getProperty(LTPAKeyFileUtility.KEYIMPORT_PUBLICKEY);
        if (publicKeyStr == null || publicKeyStr.isEmpty()) {
            return false; // no RSA key present; not applicable
        }
        try {
            byte[] publicKeyBytes = com.ibm.ws.common.encoder.Base64Coder.base64DecodeString(publicKeyStr);
            int storedLen = publicKeyBytes.length;
            // LTPA public key format: [optional 0x00 sign byte] + modulus (classicalKeySize bytes) + 3-byte exponent (65537).
            // BigInteger.toByteArray() prepends a 0x00 sign byte when the high bit of the modulus is set,
            // so the encoded length is either classicalKeySize+3 or classicalKeySize+4.
            return storedLen != classicalKeySize + 3 && storedLen != classicalKeySize + 4;
        } catch (Exception e) {
            if (tc.isDebugEnabled()) {
                Tr.debug(this, tc, "Could not decode RSA public key for size check: " + e);
            }
        }
        return false;
    }

    /**
     * @param props          loaded key file properties
     * @param mldsaAlgorithm configured ML-DSA algorithm (e.g. "ML-DSA-65"), or {@code null}
     * @return {@code true} if the stored key does not match the configured algorithm
     */
    private boolean isMldsaKeySizeMismatch(Properties props, String mldsaAlgorithm) {
        if (mldsaAlgorithm == null || mldsaAlgorithm.isEmpty()) {
            return false;
        }
        String publicKeyStr = props.getProperty(LTPAKeyFileUtility.KEYIMPORT_MLDSA_PUBLICKEY);
        if (publicKeyStr == null || publicKeyStr.isEmpty()) {
            return false; // no ML-DSA key present; not applicable
        }
        try {
            byte[] publicKeyBytes = com.ibm.ws.common.encoder.Base64Coder.base64DecodeString(publicKeyStr);
            int storedLen = publicKeyBytes.length;

            // Derive the stored algorithm from the key length using midpoint thresholds.
            String storedAlgorithm;
            if (storedLen <= MLDSA_44_65_THRESHOLD) {
                storedAlgorithm = "ML-DSA-44";
            } else if (storedLen <= MLDSA_65_87_THRESHOLD) {
                storedAlgorithm = "ML-DSA-65";
            } else {
                storedAlgorithm = "ML-DSA-87";
            }

            return !mldsaAlgorithm.equals(storedAlgorithm);
        } catch (Exception e) {
            if (tc.isDebugEnabled()) {
                Tr.debug(this, tc, "Could not decode ML-DSA public key for size check: " + e);
            }
        }
        return false;
    }

    /**
     * @param locService
     * @param keyImportFile
     * @param keyPassword
     * @return
     * @throws Exception
     */
    private Properties createPrimaryKeyFile(WsLocationAdmin locService, String keyImportFile, @Sensitive byte[] keyPassword, String signingMode, String mldsaAlgorithm, int classicalKeySize) throws Exception {
        long start = System.currentTimeMillis();
        Tr.info(tc, "LTPA_CREATE_KEYS_START");

        LTPAKeyFileCreator creator = new LTPAKeyFileCreatorImpl();
        Properties props;
        if ("pqc".equals(signingMode)) {
            props = creator.createLTPAKeysFile(locService, keyImportFile, keyPassword, mldsaAlgorithm);
        } else {
            props = creator.createLTPAKeysFile(locService, keyImportFile, keyPassword, classicalKeySize);
        }

        Tr.audit(tc, "LTPA_CREATE_KEYS_COMPLETE", TimestampUtils.getElapsedTime(start), keyImportFile);
        return props;
    }

    /**
     * Given the path to the LTPA key file return the WsResource for the file
     * if the file exists.
     *
     * @param ltpaKeyFile
     *
     * @return WsResource if the file exist, null if it does not.
     */
    final WsResource getLTPAKeyFileResource(WsLocationAdmin locService, String ltpaKeyFile) {
        WsResource ltpaFile = locService.resolveResource(ltpaKeyFile);
        if (ltpaFile != null && ltpaFile.exists()) {
            return ltpaFile;
        } else {
            return null;
        }
    }

    /**
     * Get the LTPA secret key.
     *
     * @param keyImportFile The URL of the key import file. If it's not the URL, it is assumed as a relative path from
     *                          ${App.root}/config
     * @return The LTPA secret key
     */
    @Sensitive
    public final byte[] getSecretKey(String keyImportFile) {
        return this.keyCache.get(keyImportFile + SECRETKEY);
    }

    /**
     * Get the LTPA private key.
     *
     * @param keyImportFile The URL of the key import file. If it's not the URL, it is assumed as a relative path from
     *                          ${App.root}/config
     * @return The LTPA private key
     */
    @Sensitive
    public final byte[] getPrivateKey(String keyImportFile) {
        return this.keyCache.get(keyImportFile + PRIVATEKEY);
    }

    /**
     * Get the LTPA public key.
     *
     * @param keyImportFile The URL of the key import file. If it's not the URL, it is assumed as a relative path from
     *                          ${App.root}/config
     * @return The LTPA public key
     */
    public final byte[] getPublicKey(String keyImportFile) {
        return this.keyCache.get(keyImportFile + PUBLICKEY);
    }

    /**
     * Get the LTPA realm.
     *
     * @param keyImportFile The URL of the key import file. If it's not the URL, it is assumed as a relative path from
     *                          ${App.root}/config
     * @return The LTPA realm
     */
    final String getRealm(String keyImportFile) {
        return this.realmCache.get(keyImportFile);
    }

    public final List<LTPAValidationKeysInfo> getValidationLTPAKeys() {
        return ltpaValidationKeysInfos;
    }

    /**
         * Get ML-DSA private key from cache.
         *
         * @param keyImportFile The key file name
         * @return ML-DSA private key bytes or null if not present
         */
        public byte[] getMLDSAPrivateKey(String keyImportFile) {
                return this.keyCache.get(keyImportFile + MLDSA_PRIVATEKEY);
        }

        /**
         * Get ML-DSA public key from cache.
         *
         * @param keyImportFile The key file name
         * @return ML-DSA public key bytes or null if not present
         */
        public byte[] getMLDSAPublicKey(String keyImportFile) {
                return this.keyCache.get(keyImportFile + MLDSA_PUBLICKEY);
        }

}
