package com.hsbc.authService;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

public class UserGroup {
    private HashMap<String, String> m_user_password;
    private HashMap<String, String> m_user_token; // prevent iteration through every element of the user, user and token should be a 1 to 1 correspondence
    private boolean m_is_key_set;
    private boolean m_is_iv_set;
    // The secret key and the iv should be passed safely to the clients to encrypt and decrypt passwords
    private static SecretKey m_secret_key;
    private static IvParameterSpec m_iv;

    UserGroup() {
        m_user_password = new HashMap<>();
        m_user_token = new HashMap<>();
        m_is_key_set = false;
        m_is_iv_set = false;
    }

    public int getGroupSize() {
        return m_user_password.size();
    }

    public boolean createUser(String user_name, String password) {
        // generate the encryption tokens if nonexistent
        if (m_is_key_set == false) {
            try {
                m_secret_key = StringEncryption.generateKey(128);
                m_is_key_set = true;
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        if (m_is_iv_set == false) {
            m_iv = StringEncryption.generateIv();
            m_is_iv_set = true;
        }
        // each username is unique
        if (m_user_password.containsKey(user_name)) {
            System.out.println("ERROR: USER ALREADY EXISTS.");
            return false;
        } else {
            try {
                String encrypted_pass = StringEncryption.encrypt("AES/CBC/PKCS5Padding", password, m_secret_key, m_iv);
                m_user_password.put(user_name, encrypted_pass);
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            }
            System.out.println("Number of users: " + m_user_password.size());
            return true;
        }
    }

    public boolean removeUser(String username) {
        if (m_user_password.containsKey(username)) {
            m_user_password.remove(username);
            System.out.println("Number of users: " + m_user_password.size());
            if (m_user_token.containsKey(username) == true) {
                m_user_token.remove(username);
            }
            return true;
        } else {
            System.out.println("ERROR: USERNAME NOT IN GROUP");
            return false;
        }
    }

    public boolean userExists(String username) {
        return m_user_password.containsKey(username);
    }

    public boolean verifyPassword(String username, String password) {
        if(m_user_password.containsKey(username) == false) {
            System.out.println("ERROR: USERNAME NOT AVAILABLE");
            return false;
        } else {
            try {
                String encrypted_pass = StringEncryption.encrypt("AES/CBC/PKCS5Padding", password, m_secret_key, m_iv);
                System.out.println("The stored password: " + m_user_password.get(username));
                System.out.println("Passed in password: " + encrypted_pass);
                if (encrypted_pass.equals(m_user_password.get(username))) {
                    System.out.println("Same");
                    return true;
                } else {
                    System.out.println("Different");
                    return false;
                }
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            }
        }
        return false;
    }
    public void createToken(String username, String token) {
        if (m_user_token.containsKey(username)) {
            m_user_token.remove(username);
            m_user_token.put(username, token);
        } else {
            m_user_token.put(username, token);
        }
        System.out.println(m_user_token);
    }
    public String removeToken(String username) {
        if (m_user_token.containsKey(username)) {
            String old_token = m_user_token.get(username);
            m_user_token.remove(username);
            System.out.println(m_user_token);
            return old_token;
        } else {
            return "";
        }
    }
    public String getToken(String username) {
        if (m_user_token.containsKey(username)) {
            return m_user_token.get(username);
        } else {
            return "";
        }
    }


}
