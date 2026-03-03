package com.remote;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * SecurityUtils class handles AES/RSA encryption logic for secure communication.
 * This class will provide encryption and decryption methods to ensure data confidentiality.
 */
public class SecurityUtils {
    
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;      // 96-bit IV (NIST recommended)
    private static final int GCM_TAG_LENGTH = 128;     // 128-bit authentication tag
    
    /**
     * Generates a new AES SecretKey for encryption and decryption.
     * 
     * @return A newly generated SecretKey for AES encryption
     * @throws NoSuchAlgorithmException if AES algorithm is not available
     */
    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(256); // AES-256
        return keyGenerator.generateKey();
    }
    
    /**
     * Encrypts the given plaintext data using AES-GCM encryption.
     * A random 12-byte IV is generated per call and prepended to the ciphertext,
     * ensuring identical plaintexts produce different ciphertexts every time.
     * GCM also appends a 128-bit authentication tag for integrity verification.
     * 
     * @param data The plaintext string to encrypt
     * @param key The SecretKey to use for encryption
     * @return Base64 encoded string containing [IV (12 bytes) || ciphertext || GCM tag]
     * @throws Exception if encryption fails
     */
    public static String encrypt(String data, SecretKey key) throws Exception {
        // Generate a unique random IV for every encryption operation
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes("UTF-8"));
        
        // Prepend IV to ciphertext: [IV || ciphertext+tag]
        byte[] combined = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);
        
        return Base64.getEncoder().encodeToString(combined);
    }
    
    /**
     * Decrypts the given Base64 encoded AES-GCM encrypted data.
     * Extracts the 12-byte IV from the beginning, then decrypts the remainder.
     * GCM automatically verifies the authentication tag — if the ciphertext has
     * been tampered with, an AEADBadTagException is thrown.
     * 
     * @param encryptedData The Base64 encoded string containing [IV || ciphertext || GCM tag]
     * @param key The SecretKey to use for decryption
     * @return The original plaintext string
     * @throws Exception if decryption fails or integrity check fails (tampered data)
     */
    public static String decrypt(String encryptedData, SecretKey key) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(encryptedData);
        
        // Extract IV from the first 12 bytes
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(decoded, 0, iv, 0, GCM_IV_LENGTH);
        
        // Extract ciphertext+tag (everything after the IV)
        byte[] ciphertext = new byte[decoded.length - GCM_IV_LENGTH];
        System.arraycopy(decoded, GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);
        
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        
        return new String(decryptedBytes, "UTF-8");
    }
    
    /**
     * Converts a SecretKey to a Base64 encoded string for transmission.
     * 
     * @param key The SecretKey to encode
     * @return Base64 encoded string representation of the key
     */
    public static String keyToString(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }
    
    /**
     * Converts a Base64 encoded string back to a SecretKey.
     * 
     * @param keyString The Base64 encoded key string
     * @return The reconstructed SecretKey
     */
    public static SecretKey stringToKey(String keyString) {
        byte[] decodedKey = Base64.getDecoder().decode(keyString);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, ALGORITHM);
    }
    
}
