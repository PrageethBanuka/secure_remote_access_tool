package tests;

import com.remote.SecurityUtils;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PublicKey;

/**
 * MitmDemo: Demonstrates a Man-in-the-Middle attack on the RSA key exchange.
 * 
 * This shows WHY certificate pinning / verification is important:
 * Without it, an attacker sitting between the client and server can swap
 * the server's RSA public key with their own, decrypt all traffic, and
 * re-encrypt it for the real server — neither side detects the interception.
 * 
 * Run with: java tests.MitmDemo
 * 
 * EDUCATIONAL PURPOSE ONLY — demonstrates a known limitation of our implementation.
 */
public class MitmDemo {

    public static void main(String[] args) throws Exception {
        System.out.println("==============================================");
        System.out.println("  MITM Attack Demonstration");
        System.out.println("  (Educational — shows why certificate");
        System.out.println("   verification is needed)");
        System.out.println("==============================================");

        // ============================================================
        // STEP 1: Normal setup — server generates its RSA key pair
        // ============================================================
        System.out.println("\n[SERVER] Generating RSA-2048 key pair...");
        KeyPair serverKeyPair = SecurityUtils.generateRSAKeyPair();
        String serverPubKeyStr = SecurityUtils.publicKeyToString(serverKeyPair.getPublic());
        System.out.println("[SERVER] Public key ready. Sending to client...");

        // ============================================================
        // STEP 2: Attacker intercepts and generates their OWN key pair
        // ============================================================
        System.out.println("\n[ATTACKER] >>> Intercepted server's public key!");
        System.out.println("[ATTACKER] Generating own RSA-2048 key pair...");
        KeyPair attackerKeyPair = SecurityUtils.generateRSAKeyPair();
        String attackerPubKeyStr = SecurityUtils.publicKeyToString(attackerKeyPair.getPublic());

        // Attacker stores server's real public key for later
        PublicKey realServerPubKey = SecurityUtils.stringToPublicKey(serverPubKeyStr);

        // Attacker sends THEIR public key to the client instead
        System.out.println("[ATTACKER] >>> Substituting server's public key with own key!");

        // ============================================================
        // STEP 3: Client receives attacker's key (thinks it's server's)
        // ============================================================
        System.out.println("\n[CLIENT] Received 'server' public key (actually attacker's)");
        PublicKey receivedPubKey = SecurityUtils.stringToPublicKey(attackerPubKeyStr);
        
        // Client generates AES session key and encrypts with the received key
        SecretKey clientAesKey = SecurityUtils.generateKey();
        String clientAesKeyStr = SecurityUtils.keyToString(clientAesKey);
        System.out.println("[CLIENT] Generated AES-256 session key");
        
        String encryptedForAttacker = SecurityUtils.encryptWithRSA(clientAesKeyStr, receivedPubKey);
        System.out.println("[CLIENT] Encrypted AES key with 'server' public key. Sending...");

        // ============================================================
        // STEP 4: Attacker decrypts with their private key, gets AES key
        // ============================================================
        System.out.println("\n[ATTACKER] >>> Intercepted encrypted AES key!");
        String stolenAesKeyStr = SecurityUtils.decryptWithRSA(encryptedForAttacker, attackerKeyPair.getPrivate());
        SecretKey stolenAesKey = SecurityUtils.stringToKey(stolenAesKeyStr);
        System.out.println("[ATTACKER] >>> DECRYPTED client's AES session key!");

        // Attacker re-encrypts the AES key with the REAL server's public key
        String reEncryptedForServer = SecurityUtils.encryptWithRSA(stolenAesKeyStr, realServerPubKey);
        System.out.println("[ATTACKER] >>> Re-encrypted AES key with real server public key. Forwarding...");

        // ============================================================
        // STEP 5: Server receives and decrypts normally — no suspicion
        // ============================================================
        System.out.println("\n[SERVER] Received encrypted AES key");
        String serverAesKeyStr = SecurityUtils.decryptWithRSA(reEncryptedForServer, serverKeyPair.getPrivate());
        SecretKey serverAesKey = SecurityUtils.stringToKey(serverAesKeyStr);
        System.out.println("[SERVER] Decrypted AES session key successfully");

        // ============================================================
        // STEP 6: Verify the attack — all three parties have the same key
        // ============================================================
        System.out.println("\n============================================");
        System.out.println("  ATTACK RESULT");
        System.out.println("============================================");

        boolean clientServerMatch = java.util.Arrays.equals(
            clientAesKey.getEncoded(), serverAesKey.getEncoded());
        boolean attackerHasKey = java.util.Arrays.equals(
            clientAesKey.getEncoded(), stolenAesKey.getEncoded());

        System.out.println("  Client & Server have same AES key: " + clientServerMatch);
        System.out.println("  Attacker also has the AES key:     " + attackerHasKey);

        // ============================================================
        // STEP 7: Demo — attacker reads encrypted messages
        // ============================================================
        System.out.println("\n--- Encrypted Communication (attacker reads everything) ---");

        String clientMsg = "whoami";
        String encryptedMsg = SecurityUtils.encrypt(clientMsg, clientAesKey);
        System.out.println("\n[CLIENT -> SERVER] Encrypted: " + encryptedMsg.substring(0, 40) + "...");

        // Server decrypts normally
        String serverDecrypted = SecurityUtils.decrypt(encryptedMsg, serverAesKey);
        System.out.println("[SERVER] Decrypted:  \"" + serverDecrypted + "\"");

        // Attacker ALSO decrypts
        String attackerDecrypted = SecurityUtils.decrypt(encryptedMsg, stolenAesKey);
        System.out.println("[ATTACKER] Decrypted: \"" + attackerDecrypted + "\"  <<< INTERCEPTED!");

        // Server responds
        String serverResp = "admin-pc\\admin";
        String encryptedResp = SecurityUtils.encrypt(serverResp, serverAesKey);
        System.out.println("\n[SERVER -> CLIENT] Encrypted: " + encryptedResp.substring(0, 40) + "...");

        // Client decrypts normally
        String clientDecrypted = SecurityUtils.decrypt(encryptedResp, clientAesKey);
        System.out.println("[CLIENT] Decrypted:  \"" + clientDecrypted + "\"");

        // Attacker also reads the response
        String attackerResp = SecurityUtils.decrypt(encryptedResp, stolenAesKey);
        System.out.println("[ATTACKER] Decrypted: \"" + attackerResp + "\"  <<< INTERCEPTED!");

        // ============================================================
        // STEP 8: Mitigation discussion
        // ============================================================
        System.out.println("\n==============================================");
        System.out.println("  WHY THIS WORKS & HOW TO PREVENT IT");
        System.out.println("==============================================");
        System.out.println("  The attack succeeds because the client has no way");
        System.out.println("  to verify that the received public key actually");
        System.out.println("  belongs to the real server.");
        System.out.println();
        System.out.println("  Mitigations:");
        System.out.println("  1. Certificate Pinning — hardcode or pre-share the");
        System.out.println("     server's public key fingerprint in the client.");
        System.out.println("  2. TLS/SSL (X.509 Certificates) — use a Certificate");
        System.out.println("     Authority to sign the server's public key.");
        System.out.println("  3. TOFU (Trust On First Use) — save the server's key");
        System.out.println("     on first connection; warn if it changes later.");
        System.out.println("  4. Out-of-band verification — verify the key");
        System.out.println("     fingerprint via a separate secure channel.");
        System.out.println("==============================================");
    }
}
