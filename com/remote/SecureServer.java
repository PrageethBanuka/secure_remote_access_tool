package com.remote;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import javax.crypto.SecretKey;

/**
 * SecureServer class provides secure remote access server functionality.
 * Based on Server.java, this class will use ProcessBuilder for command execution
 * and handle encrypted client connections.
 */
public class SecureServer {
    
    static int port = 6600;
    private static KeyPair rsaKeyPair;
    
    // Hardcoded authentication credentials
    // Password is stored as a PBKDF2-HMAC-SHA256 hash with a random salt.
    // To generate a new hash for a different password, use:
    //   byte[] salt = SecurityUtils.generateSalt();
    //   String hash = SecurityUtils.hashPassword("yourPassword", salt);
    //   String saltB64 = Base64.getEncoder().encodeToString(salt);
    private static final String ADMIN_USER = "admin";
    private static final String ADMIN_PASS_HASH = "5nqJWqZVF9cXpMs+F7zN1pJgswkjxaXO9MfMfEeJhuE=";
    private static final String ADMIN_SALT = "hSKj1xCx0ipcA8zcVVZBWw==";

    public static void main(String[] args) {
        System.out.println("\t\t Secure Remote Access Server");
        System.out.println("\t\t===========================\n\n");
        
        try {
            // Generate RSA key pair (public key sent to clients, private key stays here)
            rsaKeyPair = SecurityUtils.generateRSAKeyPair();
            System.out.println("RSA-2048 key pair generated successfully.");
            
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("Server started on port " + port);
            
            try {
                while (true) {
                    Socket socket = serverSocket.accept();
                    System.out.println("Client connected: " + socket.getInetAddress());
                    
                    // Handle each client in a separate thread
                    // Each client will negotiate its own unique AES session key
                    Thread clientThread = new Thread(new ClientHandler(socket, rsaKeyPair));
                    clientThread.start();
                }
            } finally {
                serverSocket.close();
            }
        } catch (Exception e) {
            System.err.println("Server error: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * ClientHandler class handles individual client connections in separate threads.
     */
    static class ClientHandler implements Runnable {
        private Socket socket;
        private KeyPair rsaKeyPair;

        private static final boolean IS_WINDOWS =
            System.getProperty("os.name").toLowerCase().contains("win");
        
        public ClientHandler(Socket socket, KeyPair rsaKeyPair) {
            this.socket = socket;
            this.rsaKeyPair = rsaKeyPair;
        }
        
        @Override
        public void run() {
            try {
                BufferedReader in = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

                // Per-connection working directory. Commands like `cd` must update this
                // state; spawning a new shell per command cannot persist directory changes.
                Path currentDirectory = Paths.get(System.getProperty("user.dir")).toAbsolutePath().normalize();
                

                // === RSA-OAEP Key Exchange ===
                SecretKey key;
                try {
                    // Step 1: Send RSA public key to client (Base64 encoded, X.509 format)
                    String publicKeyString = SecurityUtils.publicKeyToString(rsaKeyPair.getPublic());
                    out.println(publicKeyString);
                    
                    // Step 2: Receive client's AES session key (encrypted with our RSA public key)
                    String encryptedAesKey = in.readLine();
                    if (encryptedAesKey == null) {
                        System.err.println("Client disconnected during key exchange.");
                        socket.close();
                        return;
                    }
                    
                    // Step 3: Decrypt the AES key using our RSA private key
                    String aesKeyString = SecurityUtils.decryptWithRSA(encryptedAesKey, rsaKeyPair.getPrivate());
                    key = SecurityUtils.stringToKey(aesKeyString);
                    System.out.println("Per-client AES-256 session key established via RSA-OAEP.");
                } catch (Exception e) {
                    System.err.println("Key exchange error: " + e.getMessage());
                    socket.close();
                    return;
                }
                
                // Authentication handshake
                try {
                    // Receive encrypted username and password
                    String encryptedUsername = in.readLine();
                    String encryptedPassword = in.readLine();
                    
                    if (encryptedUsername == null || encryptedPassword == null) {
                        socket.close();
                        return;
                    }
                    
                    // Decrypt credentials
                    String username = SecurityUtils.decrypt(encryptedUsername, key);
                    String password = SecurityUtils.decrypt(encryptedPassword, key);
                    
                    // Verify credentials using PBKDF2 hash comparison
                    if (!ADMIN_USER.equals(username) || !SecurityUtils.verifyPassword(password, ADMIN_PASS_HASH, ADMIN_SALT)) {
                        System.out.println("Authentication failed for user: " + username);
                        String unauthorizedMsg = SecurityUtils.encrypt("Unauthorized", key);
                        out.println(unauthorizedMsg);
                        socket.close();
                        return;
                    }
                    
                    System.out.println("User authenticated: " + username);
                    
                    // Send authentication success message
                    String authSuccessMsg = SecurityUtils.encrypt("Authenticated", key);
                    out.println(authSuccessMsg);
                    
                } catch (Exception e) {
                    System.err.println("Authentication error: " + e.getMessage());
                    socket.close();
                    return;
                }
                
                // Send welcome message (encrypted)
                try {
                    String welcomeMsg = SecurityUtils.encrypt(
                        "Welcome to Secure Remote Access Server", key);
                    out.println(welcomeMsg);
                } catch (Exception e) {
                    System.err.println("Error sending welcome message: " + e.getMessage());
                    socket.close();
                    return;
                }
                
                // Process client commands
                String encryptedCommand;
                while ((encryptedCommand = in.readLine()) != null) {
                    try {
                        // Decrypt the incoming command
                        String command = SecurityUtils.decrypt(encryptedCommand, key);
                        System.out.println("Received command: " + command);
                        
                        // Execute command using ProcessBuilder
                        ExecResult result = executeCommand(command, currentDirectory);
                        currentDirectory = result.currentDirectory;
                        
                        // Encrypt and send response
                        String encryptedResult = SecurityUtils.encrypt(result.output, key);
                        out.println(encryptedResult);
                        
                    } catch (Exception e) {
                        try {
                            String errorMsg = "Error processing command: " + e.getMessage();
                            String encryptedError = SecurityUtils.encrypt(errorMsg, key);
                            out.println(encryptedError);
                        } catch (Exception encryptException) {
                            System.err.println("Error encrypting error message: " + encryptException.getMessage());
                        }
                    }
                }
                
            } catch (IOException e) {
                System.err.println("Client handler error: " + e.getMessage());
            } finally {
                try {
                    socket.close();
                    System.out.println("Client disconnected.");
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        
        /**
         * Executes a system command using ProcessBuilder.
         * Handles both standalone executables and shell built-in commands.
         * 
         * @param command The command string to execute
         * @return The output of the command execution
         */
        private static class ExecResult {
            private final String output;
            private final Path currentDirectory;

            private ExecResult(String output, Path currentDirectory) {
                this.output = output;
                this.currentDirectory = currentDirectory;
            }
        }

        private ExecResult executeCommand(String command, Path currentDirectory) {
            String sanitized = command == null ? "" : command.trim();
            if (sanitized.isEmpty()) {
                return new ExecResult("Exit Code: 0", currentDirectory);
            }

            // Provide a convenient way to view the current directory.
            if (sanitized.equalsIgnoreCase("pwd") || sanitized.equalsIgnoreCase("cd")) {
                return new ExecResult(currentDirectory.toString() + "\nExit Code: 0", currentDirectory);
            }

            // Special-case `cd` because it's a shell built-in and would not persist when each
            // command is executed in a new shell. We update the per-connection working directory.
            if (startsWithCd(sanitized)) {
                CdParse cdParse = parseCd(sanitized);
                ExecResult cdResult = handleCd(cdParse.cdArg, currentDirectory);
                if (cdParse.remainder == null || cdParse.remainder.isBlank()) {
                    return cdResult;
                }
                // If the user typed something like `cd .. && dir`, run the remainder in the new directory.
                ExecResult remainderResult = executeShellCommand(cdParse.remainder, cdResult.currentDirectory);
                return new ExecResult(cdResult.output + "\n" + remainderResult.output, remainderResult.currentDirectory);
            }

            return executeShellCommand(sanitized, currentDirectory);
        }

        private boolean startsWithCd(String command) {
            // `cd..` is valid in cmd.exe, so allow that as well.
            String lower = command.toLowerCase();
            return lower.equals("cd") || lower.startsWith("cd ") || lower.startsWith("cd..") || lower.startsWith("cd\\") || lower.startsWith("cd/");
        }

        private static class CdParse {
            private final String cdArg;
            private final String remainder;

            private CdParse(String cdArg, String remainder) {
                this.cdArg = cdArg;
                this.remainder = remainder;
            }
        }

        private CdParse parseCd(String command) {
            // Split on common chaining operators, keeping only the first one.
            int andIdx = command.indexOf("&&");
            int semiIdx = command.indexOf(';');
            int splitIdx = -1;
            if (andIdx >= 0 && semiIdx >= 0) {
                splitIdx = Math.min(andIdx, semiIdx);
            } else if (andIdx >= 0) {
                splitIdx = andIdx;
            } else if (semiIdx >= 0) {
                splitIdx = semiIdx;
            }

            String cdPart = splitIdx >= 0 ? command.substring(0, splitIdx).trim() : command.trim();
            String remainder = splitIdx >= 0 ? command.substring(splitIdx + (splitIdx == andIdx ? 2 : 1)).trim() : null;

            String cdArg = "";
            String lowered = cdPart.toLowerCase();
            if (lowered.equals("cd")) {
                cdArg = "";
            } else if (lowered.startsWith("cd..")) {
                cdArg = "..";
            } else if (lowered.startsWith("cd")) {
                cdArg = cdPart.substring(2).trim();
            }

            return new CdParse(cdArg, remainder);
        }

        private ExecResult handleCd(String arg, Path currentDirectory) {
            String rawArg = arg == null ? "" : arg.trim();
            Path target;

            if (rawArg.isEmpty()) {
                target = Paths.get(System.getProperty("user.home"));
            } else {
                // Common shorthand
                if (rawArg.equals("~")) {
                    rawArg = System.getProperty("user.home");
                } else if (rawArg.startsWith("~\\") || rawArg.startsWith("~/")) {
                    rawArg = System.getProperty("user.home") + rawArg.substring(1);
                }

                try {
                    Path inputPath = Paths.get(rawArg);
                    target = inputPath.isAbsolute() ? inputPath : currentDirectory.resolve(inputPath);
                } catch (InvalidPathException e) {
                    return new ExecResult("Invalid path: " + e.getMessage() + "\nExit Code: 1", currentDirectory);
                }
            }

            target = target.toAbsolutePath().normalize();

            if (!Files.exists(target)) {
                return new ExecResult("The system cannot find the path specified: " + target + "\nExit Code: 1", currentDirectory);
            }
            if (!Files.isDirectory(target)) {
                return new ExecResult("Not a directory: " + target + "\nExit Code: 1", currentDirectory);
            }

            return new ExecResult("Changed directory to: " + target + "\nExit Code: 0", target);
        }

        private ExecResult executeShellCommand(String command, Path currentDirectory) {
            StringBuilder output = new StringBuilder();

            try {
                ProcessBuilder processBuilder;

                if (IS_WINDOWS) {
                    processBuilder = new ProcessBuilder("cmd", "/c", command);
                } else {
                    processBuilder = new ProcessBuilder("sh", "-c", command);
                }

                processBuilder.directory(currentDirectory.toFile());
                processBuilder.redirectErrorStream(true);
                Process process = processBuilder.start();

                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }

                int exitCode = process.waitFor();
                output.append("Exit Code: ").append(exitCode);

            } catch (Exception e) {
                output.append("Command execution failed: ").append(e.getMessage());
            }

            return new ExecResult(output.toString(), currentDirectory);
        }
    }
}
