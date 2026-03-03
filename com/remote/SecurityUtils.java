package com.remote;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
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
    
    // RSA-OAEP: uses SHA-256 for hashing and MGF1 for mask generation.
    // OAEP avoids Bleichenbacher's chosen-ciphertext attack against PKCS#1 v1.5.
    private static final String RSA_ALGORITHM = "RSA";
    private static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final int RSA_KEY_SIZE = 2048;
    
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
    
    // ======================== RSA-OAEP Methods ========================
    
    /**
     * Generates an RSA 2048-bit key pair for asymmetric encryption.
     * The public key is sent to the client; the private key stays on the server.
     * 
     * @return A KeyPair containing the RSA public and private keys
     * @throws NoSuchAlgorithmException if RSA algorithm is not available
     */
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyPairGenerator.initialize(RSA_KEY_SIZE, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }
    
    /**
     * Converts an RSA PublicKey to a Base64 encoded string for network transmission.
     * Uses X.509 encoding format (standard for public keys).
     * 
     * @param publicKey The RSA PublicKey to encode
     * @return Base64 encoded string representation of the public key
     */
    public static String publicKeyToString(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }
    
    /**
     * Reconstructs an RSA PublicKey from a Base64 encoded string.
     * Expects X.509 encoded key data.
     * 
     * @param keyString The Base64 encoded public key string
     * @return The reconstructed RSA PublicKey
     * @throws Exception if key reconstruction fails
     */
    public static PublicKey stringToPublicKey(String keyString) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(keyString);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        return keyFactory.generatePublic(spec);
    }
    
    /**
     * Encrypts data using RSA-OAEP (Optimal Asymmetric Encryption Padding).
     * OAEP uses SHA-256 hashing and MGF1 mask generation, providing:
     * - Randomized padding (same plaintext → different ciphertext each time)
     * - Provable security against chosen-ciphertext attacks
     * - Protection against Bleichenbacher's attack (unlike PKCS#1 v1.5)
     * 
     * @param data The plaintext string to encrypt
     * @param publicKey The RSA public key to encrypt with
     * @return Base64 encoded RSA-OAEP encrypted string
     * @throws Exception if encryption fails
     */
    public static String encryptWithRSA(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
    
    /**
     * Decrypts RSA-OAEP encrypted data using the server's private key.
     * Verifies the OAEP padding structure during decryption — any tampering
     * with the ciphertext will cause a decryption failure.
     * 
     * @param encryptedData The Base64 encoded RSA-OAEP encrypted string
     * @param privateKey The RSA private key to decrypt with
     * @return The original plaintext string
     * @throws Exception if decryption fails or padding verification fails
     */
    public static String decryptWithRSA(String encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes, "UTF-8");
    }
    
}
