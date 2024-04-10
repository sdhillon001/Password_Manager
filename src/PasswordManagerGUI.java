import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;
import java.util.Base64;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import javax.swing.*;
import java.util.List;

public class PasswordManagerGUI {
    // Master password for encryption/decryption
    private static String MASTER_PASSWORD;
    // Flag to track successful authentication
    private static boolean authenticationSuccessful = false;

    // Entry point of the program
    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                authenticateMasterPassword(); // Start authentication process
                
            }
        });
    }

    private static void authenticateMasterPassword() {
        // Create the authentication window
        JFrame passwordFrame = new JFrame("Master Password");
        passwordFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        passwordFrame.setSize(400, 200);

        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(3, 1));

        JLabel passwordLabel = new JLabel("Enter master password:");
        JPasswordField passwordField = new JPasswordField();

        JButton submitButton = new JButton("Submit");
        submitButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String enteredPassword = new String(passwordField.getPassword());

                try (BufferedReader reader = new BufferedReader(new FileReader("src/Master.txt"))) { 
                    String salt = reader.readLine();
                    String storedHashedPassword = reader.readLine();

                    // Add salt to the entered password
                    String saltedPassword = salt + enteredPassword;

                    // Hash the salted password using SHA-256
                    String hashedPassword = hashPassword(saltedPassword);

                    // Compare the computed hashed password with the stored hashed password
                    if (hashedPassword.equals(storedHashedPassword)) {
                        // Store the correct master password in the public variable
                        MASTER_PASSWORD = enteredPassword;

                        authenticationSuccessful = true;
                        passwordFrame.dispose();
                        createAndShowGUI(); // Authentication successful, proceed to main UI
                    } else {
                        JOptionPane.showMessageDialog(passwordFrame, "Incorrect master password. Please try again.", "Error", JOptionPane.ERROR_MESSAGE);
                        passwordField.setText("");
                    }
                } catch (IOException ex) {
                    ex.printStackTrace();
                    JOptionPane.showMessageDialog(passwordFrame, "Error reading master password file.", "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        panel.add(passwordLabel);
        panel.add(passwordField);
        panel.add(submitButton);

        passwordFrame.getContentPane().add(BorderLayout.CENTER, panel);
        passwordFrame.setVisible(true);
    }

    // Method to hash a password using SHA-256
    private static String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(password.getBytes());
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    // Method to create and display the main UI
    private static void createAndShowGUI() {
        if (!authenticationSuccessful) {
            return; // Exit if authentication failed
        }

        JFrame frame = new JFrame("Password Manager");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 200);

        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(1, 2));

        JButton addButton = new JButton("Add New");
        addButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                addNewPassword(); // Open the "Add New Password" window
            }
        });

        JButton decryptButton = new JButton("Decrypt Password");
        decryptButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                decryptPassword(); // Open the "Decrypt Password" window
            }
        });

        panel.add(addButton);
        panel.add(decryptButton);

        frame.getContentPane().add(BorderLayout.CENTER, panel);
        frame.setVisible(true);
    }

    // Method to add a new password
    private static void addNewPassword() {
        JFrame addFrame = new JFrame("Add New Password");
        addFrame.setSize(400, 200);

        JPanel addPanel = new JPanel();
        addPanel.setLayout(new GridLayout(4, 2));

        JLabel applicationLabel = new JLabel("Application Name:");
        JTextField applicationField = new JTextField();

        JLabel usernameLabel = new JLabel("Username:");
        JTextField usernameField = new JTextField();

        JLabel passwordLabel = new JLabel("Password:");
        JPasswordField passwordField = new JPasswordField();

        JButton saveButton = new JButton("Save");
        saveButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String applicationName = applicationField.getText();
                String username = usernameField.getText();
                String password = new String(passwordField.getPassword());

                if (!applicationName.isEmpty() && !username.isEmpty() && !password.isEmpty()) {
                    try {
                        String encryptedPassword = encryptPassword(password);

                        // Write the encrypted password to file
                        try (FileWriter writer = new FileWriter("src/passwords.txt", true)) {
                            writer.write(applicationName + "|" + username + "|" + encryptedPassword + "\n");
                            JOptionPane.showMessageDialog(addFrame, "Password saved successfully!");
                            addFrame.dispose();
                        } catch (IOException ex) {
                            JOptionPane.showMessageDialog(addFrame, "Error writing to file: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                        }
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(addFrame, "Error encrypting password: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                    }
                } else {
                    JOptionPane.showMessageDialog(addFrame, "Please fill in all fields.", "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        addPanel.add(applicationLabel);
        addPanel.add(applicationField);
        addPanel.add(usernameLabel);
        addPanel.add(usernameField);
        addPanel.add(passwordLabel);
        addPanel.add(passwordField);
        addPanel.add(new JLabel(""));
        addPanel.add(saveButton);

        addFrame.getContentPane().add(BorderLayout.CENTER, addPanel);
        addFrame.setVisible(true);
    }

    // Method to decrypt a password
    private static void decryptPassword() {
        JFrame decryptFrame = new JFrame("Decrypt Password");
        decryptFrame.setSize(400, 200);

        // Read passwords from file and display unique application names as buttons
        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new GridLayout(0, 1));
        Set<String> uniqueApplicationNames = new HashSet<>();

        try (Scanner scanner = new Scanner(new File("src/passwords.txt"))) {
            while (scanner.hasNextLine()) {
                String[] parts = scanner.nextLine().split("\\|");
                String applicationName = parts[0];
                uniqueApplicationNames.add(applicationName);
            }
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(decryptFrame, "Error reading file: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }

        for (String applicationName : uniqueApplicationNames) {
            JButton button = new JButton(applicationName);
            button.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    showUsernames(applicationName); // Show usernames for the selected application
                }
            });
            buttonPanel.add(button);
        }

        decryptFrame.getContentPane().add(BorderLayout.CENTER, buttonPanel);
        decryptFrame.setVisible(true);
    }

    // Method to show usernames for a given application
    private static void showUsernames(String applicationName) {
        JFrame usernamesFrame = new JFrame("Usernames for " + applicationName);
        usernamesFrame.setSize(400, 200);

        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new GridLayout(0, 1));

        try (Scanner scanner = new Scanner(new File("src/passwords.txt"))) {
            while (scanner.hasNextLine()) {
                String[] parts = scanner.nextLine().split("\\|");
                if (parts[0].equals(applicationName)) {
                    String username = parts[1];
                    String password = decryptPassword(parts[2]);

                    JButton button = new JButton(username);
                    button.addActionListener(new ActionListener() {
                        public void actionPerformed(ActionEvent e) {
                            showUsernameAndPassword(username, password); // Show username and password details
                        }
                    });

                    buttonPanel.add(button);
                }
            }
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(usernamesFrame, "Error reading file: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }

        usernamesFrame.getContentPane().add(BorderLayout.CENTER, buttonPanel);
        usernamesFrame.setVisible(true);
    }

    // Method to show username and password details
    private static void showUsernameAndPassword(String username, String password) {
        JFrame detailsFrame = new JFrame("Username and Password");
        detailsFrame.setSize(500, 300);

        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(2, 2));

        JTextField usernameField = new JTextField(username);
        JTextField passwordField = new JTextField(password);

        usernameField.setEditable(false);
        passwordField.setEditable(false);

        panel.add(new JLabel("Username:"));
        panel.add(usernameField);
        panel.add(new JLabel("Password:"));
        panel.add(passwordField);

        detailsFrame.getContentPane().add(BorderLayout.CENTER, panel);
        detailsFrame.setVisible(true);
    }


    // Method to decrypt a password
    private static String decryptPassword(String encryptedPassword) {
        try {
            // Decode Base64 string to obtain encrypted bytes
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedPassword);

            // Generate AES key from the master password
            SecretKeySpec secretKeySpec = generateAESKey(MASTER_PASSWORD);

            // Create AES cipher instance
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

            // Decrypt the password
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            // Convert decrypted bytes to plaintext password
            return new String(decryptedBytes);
        } catch (Exception ex) {
            return "Error decrypting password: " + ex.getMessage();
        }
    }

    // Method to encrypt a password
    private static String encryptPassword(String password) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        // Generate AES key from the master password
        SecretKeySpec secretKeySpec = generateAESKey(MASTER_PASSWORD);

        // Create AES cipher instance
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        // Encrypt the password
        byte[] encryptedBytes = cipher.doFinal(password.getBytes());

        // Encode encrypted bytes to Base64 string for storage
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Method to generate an AES key from the master password
    private static SecretKeySpec generateAESKey(String masterPassword) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        // Derive AES key from master password using SHA-256 hash
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha256.digest(masterPassword.getBytes("UTF-8"));
        return new SecretKeySpec(keyBytes, "AES");
    }
}
