package tests;

import com.remote.SecurityUtils;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;

/**
 * Comprehensive test suite for SecurityUtils cryptographic operations.
 * Tests cover: AES-GCM, RSA-OAEP, PBKDF2, key serialization, and tamper detection.
 * 
 * Run with: java tests.SecurityUtilsTest
 * 
 * Each test prints PASS or FAIL. A summary is printed at the end.
 */
public class SecurityUtilsTest {

    private static int passed = 0;
    private static int failed = 0;

    // ================= Test Runner Helpers =================

    private static void assertTest(String name, boolean condition) {
        if (condition) {
            System.out.println("  [PASS] " + name);
            passed++;
        } else {
            System.out.println("  [FAIL] " + name);
            failed++;
        }
    }

    private static void assertThrows(String name, Class<? extends Exception> expectedType, Runnable code) {
        try {
            code.run();
            System.out.println("  [FAIL] " + name + " (no exception thrown)");
            failed++;
        } catch (Exception e) {
            // GCM wraps AEADBadTagException inside other exceptions sometimes
            Throwable cause = e;
            boolean match = false;
            while (cause != null) {
                if (expectedType.isInstance(cause)) {
                    match = true;
                    break;
                }
                cause = cause.getCause();
            }
            if (match || e.getClass().getName().contains("BadTag") || 
                (e.getCause() != null && e.getCause().getClass().getName().contains("BadTag"))) {
                System.out.println("  [PASS] " + name);
                passed++;
            } else if (expectedType == Exception.class) {
                // Generic exception expected — any exception is fine
                System.out.println("  [PASS] " + name + " (threw " + e.getClass().getSimpleName() + ")");
                passed++;
            } else {
                System.out.println("  [FAIL] " + name + " (expected " + expectedType.getSimpleName() 
                    + " but got " + e.getClass().getSimpleName() + ": " + e.getMessage() + ")");
                failed++;
            }
        }
    }

    // ================= AES-GCM Tests =================

    private static void testAesGcmRoundTrip() {
        System.out.println("\n--- AES-GCM Round-Trip Tests ---");
        try {
            SecretKey key = SecurityUtils.generateKey();
            String plaintext = "Hello, Secure World!";
            String encrypted = SecurityUtils.encrypt(plaintext, key);
            String decrypted = SecurityUtils.decrypt(encrypted, key);

            assertTest("Encrypt/decrypt round-trip produces original plaintext", 
                plaintext.equals(decrypted));
        } catch (Exception e) {
            assertTest("Encrypt/decrypt round-trip (exception: " + e.getMessage() + ")", false);
        }
    }

    private static void testAesGcmEmptyString() {
        System.out.println("\n--- AES-GCM Empty String Test ---");
        try {
            SecretKey key = SecurityUtils.generateKey();
            String plaintext = "";
            String encrypted = SecurityUtils.encrypt(plaintext, key);
            String decrypted = SecurityUtils.decrypt(encrypted, key);

            assertTest("Empty string encrypts and decrypts correctly", 
                plaintext.equals(decrypted));
        } catch (Exception e) {
            assertTest("Empty string round-trip (exception: " + e.getMessage() + ")", false);
        }
    }

    private static void testAesGcmLongString() {
        System.out.println("\n--- AES-GCM Long String Test ---");
        try {
            SecretKey key = SecurityUtils.generateKey();
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 10000; i++) sb.append("A");
            String plaintext = sb.toString();
            String encrypted = SecurityUtils.encrypt(plaintext, key);
            String decrypted = SecurityUtils.decrypt(encrypted, key);

            assertTest("10,000-char string encrypts and decrypts correctly", 
                plaintext.equals(decrypted));
        } catch (Exception e) {
            assertTest("Long string round-trip (exception: " + e.getMessage() + ")", false);
        }
    }

    private static void testAesGcmUnicode() {
        System.out.println("\n--- AES-GCM Unicode Test ---");
        try {
            SecretKey key = SecurityUtils.generateKey();
            String plaintext = "Hello \u4e16\u754c \ud83d\udd12 \u00e9\u00e8\u00ea"; // Chinese, emoji, accented chars
            String encrypted = SecurityUtils.encrypt(plaintext, key);
            String decrypted = SecurityUtils.decrypt(encrypted, key);

            assertTest("Unicode characters survive encrypt/decrypt", 
                plaintext.equals(decrypted));
        } catch (Exception e) {
            assertTest("Unicode round-trip (exception: " + e.getMessage() + ")", false);
        }
    }

    private static void testAesGcmRandomIV() {
        System.out.println("\n--- AES-GCM Random IV Test ---");
        try {
            SecretKey key = SecurityUtils.generateKey();
            String plaintext = "same plaintext";

            String encrypted1 = SecurityUtils.encrypt(plaintext, key);
            String encrypted2 = SecurityUtils.encrypt(plaintext, key);

            // Same plaintext must produce DIFFERENT ciphertexts (due to random IV)
            assertTest("Same plaintext produces different ciphertexts (random IV)", 
                !encrypted1.equals(encrypted2));

            // But both should decrypt to the same plaintext
            assertTest("Both ciphertexts decrypt to same plaintext", 
                SecurityUtils.decrypt(encrypted1, key).equals(SecurityUtils.decrypt(encrypted2, key)));
        } catch (Exception e) {
            assertTest("Random IV test (exception: " + e.getMessage() + ")", false);
        }
    }

    private static void testAesGcmWrongKey() {
        System.out.println("\n--- AES-GCM Wrong Key Test ---");
        try {
            SecretKey key1 = SecurityUtils.generateKey();
            SecretKey key2 = SecurityUtils.generateKey();
            String plaintext = "secret data";
            String encrypted = SecurityUtils.encrypt(plaintext, key1);

            assertThrows("Decrypting with wrong key throws exception", 
                Exception.class, () -> {
                    try {
                        SecurityUtils.decrypt(encrypted, key2);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });
        } catch (Exception e) {
            assertTest("Wrong key test setup (exception: " + e.getMessage() + ")", false);
        }
    }

    // ================= GCM Tamper Detection Tests =================

    private static void testGcmTamperCiphertext() {
        System.out.println("\n--- GCM Tamper Detection: Ciphertext ---");
        try {
            SecretKey key = SecurityUtils.generateKey();
            String encrypted = SecurityUtils.encrypt("integrity test", key);
            byte[] raw = Base64.getDecoder().decode(encrypted);

            // Flip a bit in the ciphertext portion (after the 12-byte IV)
            int tamperIndex = 12 + (raw.length - 12) / 2; // middle of ciphertext
            raw[tamperIndex] ^= 0x01; // flip one bit

            String tampered = Base64.getEncoder().encodeToString(raw);

            assertThrows("Tampered ciphertext causes AEADBadTagException", 
                AEADBadTagException.class, () -> {
                    try {
                        SecurityUtils.decrypt(tampered, key);
                    } catch (Exception e) {
                        throw e instanceof RuntimeException ? (RuntimeException) e : new RuntimeException(e);
                    }
                });
        } catch (Exception e) {
            assertTest("Tamper ciphertext test setup (exception: " + e.getMessage() + ")", false);
        }
    }

    private static void testGcmTamperIV() {
        System.out.println("\n--- GCM Tamper Detection: IV ---");
        try {
            SecretKey key = SecurityUtils.generateKey();
            String encrypted = SecurityUtils.encrypt("iv tamper test", key);
            byte[] raw = Base64.getDecoder().decode(encrypted);

            // Flip a bit in the IV portion (first 12 bytes)
            raw[5] ^= 0x01;

            String tampered = Base64.getEncoder().encodeToString(raw);

            assertThrows("Tampered IV causes decryption failure", 
                AEADBadTagException.class, () -> {
                    try {
                        SecurityUtils.decrypt(tampered, key);
                    } catch (Exception e) {
                        throw e instanceof RuntimeException ? (RuntimeException) e : new RuntimeException(e);
                    }
                });
        } catch (Exception e) {
            assertTest("Tamper IV test setup (exception: " + e.getMessage() + ")", false);
        }
    }

    private static void testGcmTamperTag() {
        System.out.println("\n--- GCM Tamper Detection: Auth Tag ---");
        try {
            SecretKey key = SecurityUtils.generateKey();
            String encrypted = SecurityUtils.encrypt("tag tamper test", key);
            byte[] raw = Base64.getDecoder().decode(encrypted);

            // Flip a bit in the last byte (part of the GCM auth tag)
            raw[raw.length - 1] ^= 0x01;

            String tampered = Base64.getEncoder().encodeToString(raw);

            assertThrows("Tampered auth tag causes AEADBadTagException", 
                AEADBadTagException.class, () -> {
                    try {
                        SecurityUtils.decrypt(tampered, key);
                    } catch (Exception e) {
                        throw e instanceof RuntimeException ? (RuntimeException) e : new RuntimeException(e);
                    }
                });
        } catch (Exception e) {
            assertTest("Tamper tag test setup (exception: " + e.getMessage() + ")", false);
        }
    }

    // ================= RSA-OAEP Tests =================

    private static void testRsaOaepRoundTrip() {
        System.out.println("\n--- RSA-OAEP Round-Trip Test ---");
        try {
            KeyPair keyPair = SecurityUtils.generateRSAKeyPair();
            String plaintext = "AES key material for exchange";
            
            String encrypted = SecurityUtils.encryptWithRSA(plaintext, keyPair.getPublic());
            String decrypted = SecurityUtils.decryptWithRSA(encrypted, keyPair.getPrivate());

            assertTest("RSA-OAEP encrypt/decrypt round-trip", 
                plaintext.equals(decrypted));
        } catch (Exception e) {
            assertTest("RSA-OAEP round-trip (exception: " + e.getMessage() + ")", false);
        }
    }

    private static void testRsaOaepRandomPadding() {
        System.out.println("\n--- RSA-OAEP Random Padding Test ---");
        try {
            KeyPair keyPair = SecurityUtils.generateRSAKeyPair();
            String plaintext = "same data";

            String encrypted1 = SecurityUtils.encryptWithRSA(plaintext, keyPair.getPublic());
            String encrypted2 = SecurityUtils.encryptWithRSA(plaintext, keyPair.getPublic());

            // OAEP uses random padding → same plaintext produces different ciphertexts
            assertTest("RSA-OAEP same plaintext produces different ciphertexts", 
                !encrypted1.equals(encrypted2));

            // Both should decrypt correctly
            assertTest("Both RSA ciphertexts decrypt to same plaintext",
                SecurityUtils.decryptWithRSA(encrypted1, keyPair.getPrivate()).equals(
                    SecurityUtils.decryptWithRSA(encrypted2, keyPair.getPrivate())));
        } catch (Exception e) {
            assertTest("RSA-OAEP random padding (exception: " + e.getMessage() + ")", false);
        }
    }

    private static void testRsaOaepWrongKey() {
        System.out.println("\n--- RSA-OAEP Wrong Key Test ---");
        try {
            KeyPair keyPair1 = SecurityUtils.generateRSAKeyPair();
            KeyPair keyPair2 = SecurityUtils.generateRSAKeyPair();
            String plaintext = "secret";

            String encrypted = SecurityUtils.encryptWithRSA(plaintext, keyPair1.getPublic());

            assertThrows("Decrypting with wrong RSA private key throws exception",
                Exception.class, () -> {
                    try {
                        SecurityUtils.decryptWithRSA(encrypted, keyPair2.getPrivate());
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });
        } catch (Exception e) {
            assertTest("RSA wrong key test setup (exception: " + e.getMessage() + ")", false);
        }
    }

    // ================= Key Serialization Tests =================

    private static void testAesKeySerialization() {
        System.out.println("\n--- AES Key Serialization Test ---");
        try {
            SecretKey original = SecurityUtils.generateKey();
            String keyString = SecurityUtils.keyToString(original);
            SecretKey restored = SecurityUtils.stringToKey(keyString);

            assertTest("AES key survives serialization/deserialization",
                java.util.Arrays.equals(original.getEncoded(), restored.getEncoded()));

            // Verify the restored key actually works for encryption/decryption
            String plaintext = "key serialization test";
            String encrypted = SecurityUtils.encrypt(plaintext, original);
            String decrypted = SecurityUtils.decrypt(encrypted, restored);

            assertTest("Restored AES key can decrypt data encrypted with original",
                plaintext.equals(decrypted));
        } catch (Exception e) {
            assertTest("AES key serialization (exception: " + e.getMessage() + ")", false);
        }
    }

    private static void testRsaPublicKeySerialization() {
        System.out.println("\n--- RSA Public Key Serialization Test ---");
        try {
            KeyPair keyPair = SecurityUtils.generateRSAKeyPair();
            PublicKey original = keyPair.getPublic();

            String keyString = SecurityUtils.publicKeyToString(original);
            PublicKey restored = SecurityUtils.stringToPublicKey(keyString);

            assertTest("RSA public key survives serialization/deserialization",
                java.util.Arrays.equals(original.getEncoded(), restored.getEncoded()));

            // Verify the restored public key works for encryption
            String plaintext = "public key serialization test";
            String encrypted = SecurityUtils.encryptWithRSA(plaintext, restored);
            String decrypted = SecurityUtils.decryptWithRSA(encrypted, keyPair.getPrivate());

            assertTest("Restored RSA public key encrypts data that private key can decrypt",
                plaintext.equals(decrypted));
        } catch (Exception e) {
            assertTest("RSA public key serialization (exception: " + e.getMessage() + ")", false);
        }
    }

    // ================= PBKDF2 Tests =================

    private static void testPbkdf2CorrectPassword() {
        System.out.println("\n--- PBKDF2 Correct Password Test ---");
        try {
            String password = "mySecurePassword123!";
            byte[] salt = SecurityUtils.generateSalt();
            String hash = SecurityUtils.hashPassword(password, salt);
            String saltB64 = Base64.getEncoder().encodeToString(salt);

            assertTest("Correct password verifies successfully",
                SecurityUtils.verifyPassword(password, hash, saltB64));
        } catch (Exception e) {
            assertTest("PBKDF2 correct password (exception: " + e.getMessage() + ")", false);
        }
    }

    private static void testPbkdf2WrongPassword() {
        System.out.println("\n--- PBKDF2 Wrong Password Test ---");
        try {
            String password = "correctPassword";
            byte[] salt = SecurityUtils.generateSalt();
            String hash = SecurityUtils.hashPassword(password, salt);
            String saltB64 = Base64.getEncoder().encodeToString(salt);

            assertTest("Wrong password is rejected",
                !SecurityUtils.verifyPassword("wrongPassword", hash, saltB64));
        } catch (Exception e) {
            assertTest("PBKDF2 wrong password (exception: " + e.getMessage() + ")", false);
        }
    }

    private static void testPbkdf2UniqueSalts() {
        System.out.println("\n--- PBKDF2 Unique Salts Test ---");
        try {
            byte[] salt1 = SecurityUtils.generateSalt();
            byte[] salt2 = SecurityUtils.generateSalt();

            assertTest("Two generated salts are different",
                !java.util.Arrays.equals(salt1, salt2));

            // Same password with different salts should produce different hashes
            String password = "samePassword";
            String hash1 = SecurityUtils.hashPassword(password, salt1);
            String hash2 = SecurityUtils.hashPassword(password, salt2);

            assertTest("Same password with different salts produces different hashes",
                !hash1.equals(hash2));
        } catch (Exception e) {
            assertTest("PBKDF2 unique salts (exception: " + e.getMessage() + ")", false);
        }
    }

    private static void testPbkdf2Deterministic() {
        System.out.println("\n--- PBKDF2 Deterministic Test ---");
        try {
            String password = "deterministicTest";
            byte[] salt = SecurityUtils.generateSalt();

            String hash1 = SecurityUtils.hashPassword(password, salt);
            String hash2 = SecurityUtils.hashPassword(password, salt);

            assertTest("Same password + same salt produces same hash (deterministic)",
                hash1.equals(hash2));
        } catch (Exception e) {
            assertTest("PBKDF2 deterministic (exception: " + e.getMessage() + ")", false);
        }
    }

    private static void testPbkdf2StoredCredentials() {
        System.out.println("\n--- PBKDF2 Stored Credentials Test (Server Values) ---");
        try {
            // These are the actual values stored in SecureServer.java
            String storedHash = "5nqJWqZVF9cXpMs+F7zN1pJgswkjxaXO9MfMfEeJhuE=";
            String storedSalt = "hSKj1xCx0ipcA8zcVVZBWw==";

            assertTest("Stored hash verifies against 'secure123'",
                SecurityUtils.verifyPassword("secure123", storedHash, storedSalt));

            assertTest("Stored hash rejects wrong password 'password123'",
                !SecurityUtils.verifyPassword("password123", storedHash, storedSalt));

            assertTest("Stored hash rejects empty password",
                !SecurityUtils.verifyPassword("", storedHash, storedSalt));
        } catch (Exception e) {
            assertTest("PBKDF2 stored credentials (exception: " + e.getMessage() + ")", false);
        }
    }

    // ================= Hybrid Flow Simulation =================

    private static void testHybridKeyExchangeSimulation() {
        System.out.println("\n--- Hybrid RSA+AES Key Exchange Simulation ---");
        try {
            // ---- SERVER SIDE ----
            // Server generates RSA key pair
            KeyPair serverKeyPair = SecurityUtils.generateRSAKeyPair();
            // Server sends public key as string (simulating network transmission)
            String publicKeyString = SecurityUtils.publicKeyToString(serverKeyPair.getPublic());

            // ---- CLIENT SIDE ----
            // Client receives public key string and reconstructs it
            PublicKey serverPublicKey = SecurityUtils.stringToPublicKey(publicKeyString);
            // Client generates a fresh AES key
            SecretKey clientAesKey = SecurityUtils.generateKey();
            // Client encrypts AES key with server's RSA public key
            String encryptedAesKey = SecurityUtils.encryptWithRSA(
                SecurityUtils.keyToString(clientAesKey), serverPublicKey);

            // ---- SERVER SIDE (again) ----
            // Server decrypts the AES key with its private key
            String decryptedAesKeyStr = SecurityUtils.decryptWithRSA(
                encryptedAesKey, serverKeyPair.getPrivate());
            SecretKey serverAesKey = SecurityUtils.stringToKey(decryptedAesKeyStr);

            // Now both sides should have the same AES key
            assertTest("Server and Client have identical AES keys after exchange",
                java.util.Arrays.equals(clientAesKey.getEncoded(), serverAesKey.getEncoded()));

            // ---- Encrypted Communication ----
            // Client sends encrypted message
            String clientMessage = "whoami";
            String encryptedMsg = SecurityUtils.encrypt(clientMessage, clientAesKey);
            // Server decrypts with its copy of the AES key
            String decryptedMsg = SecurityUtils.decrypt(encryptedMsg, serverAesKey);

            assertTest("Server decrypts client message correctly",
                clientMessage.equals(decryptedMsg));

            // Server sends encrypted response
            String serverResponse = "admin-pc\\admin";
            String encryptedResp = SecurityUtils.encrypt(serverResponse, serverAesKey);
            // Client decrypts with its AES key
            String decryptedResp = SecurityUtils.decrypt(encryptedResp, clientAesKey);

            assertTest("Client decrypts server response correctly",
                serverResponse.equals(decryptedResp));

        } catch (Exception e) {
            assertTest("Hybrid key exchange simulation (exception: " + e.getMessage() + ")", false);
        }
    }

    // ================= Main =================

    public static void main(String[] args) {
        System.out.println("========================================");
        System.out.println("  SecurityUtils Test Suite");
        System.out.println("  Testing: AES-GCM, RSA-OAEP, PBKDF2");
        System.out.println("========================================");

        // AES-GCM tests
        testAesGcmRoundTrip();
        testAesGcmEmptyString();
        testAesGcmLongString();
        testAesGcmUnicode();
        testAesGcmRandomIV();
        testAesGcmWrongKey();

        // GCM integrity / tamper detection
        testGcmTamperCiphertext();
        testGcmTamperIV();
        testGcmTamperTag();

        // RSA-OAEP tests
        testRsaOaepRoundTrip();
        testRsaOaepRandomPadding();
        testRsaOaepWrongKey();

        // Key serialization tests
        testAesKeySerialization();
        testRsaPublicKeySerialization();

        // PBKDF2 tests
        testPbkdf2CorrectPassword();
        testPbkdf2WrongPassword();
        testPbkdf2UniqueSalts();
        testPbkdf2Deterministic();
        testPbkdf2StoredCredentials();

        // Hybrid flow
        testHybridKeyExchangeSimulation();

        // Summary
        System.out.println("\n========================================");
        System.out.println("  RESULTS: " + passed + " passed, " + failed + " failed");
        System.out.println("  Total:   " + (passed + failed) + " tests");
        System.out.println("========================================");

        if (failed > 0) {
            System.exit(1);
        }
    }
}
