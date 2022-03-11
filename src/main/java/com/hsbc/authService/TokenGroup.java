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


public class TokenGroup {
    private boolean m_is_key_set;
    private boolean m_is_iv_set;
    private static SecretKey m_secret_key;
    private static IvParameterSpec m_iv;
    private HashMap<String, String> m_token_user;
    private static final String TOKEN_SEPARATOR = ":-:";
    private static final int TOKEN_VALID_TIME = 2 * 60 * 60;

    TokenGroup() {
        m_is_key_set = false;
        m_is_iv_set = false;
        m_token_user = new HashMap<>();
    }

    /**
     *
     * @param username
     * @return
     */
    public String authenticate(String username) {
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
        long cur_time = System.currentTimeMillis() / 1000l;
        String cur_times = Long.toString(cur_time);
        String token = null;
        try {
            token = StringEncryption.encrypt("AES/CBC/PKCS5Padding", username + TOKEN_SEPARATOR + cur_times, m_secret_key, m_iv);
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
        m_token_user.put(token, username);
        System.out.println(m_token_user);
        return token;
    }

    public String removeToken(String token) {
        if (m_token_user.containsKey(token) == true) {
            String username = m_token_user.get(token);
            System.out.println("Removing old token from token: " + token);
            m_token_user.remove(token);
            System.out.println(m_token_user);
            return username;
        } else {
            return "";
        }
    }
    /**
     * @param token
     * @return token is invalid if the "" is returned, token is invalid if the username is returned
     */
    public String isTokenValid(String token) {
        try {
            String decrypted_token = StringEncryption.decrypt("AES/CBC/PKCS5Padding", token, m_secret_key, m_iv);
            System.out.println("The decrypted token is: " + decrypted_token);
            String elapsed_time_s = decrypted_token.substring(decrypted_token.indexOf(TOKEN_SEPARATOR) + 3);
            Long elapsed_time_l = Long.parseLong(elapsed_time_s);
            Long cur_time_l = System.currentTimeMillis() / 1000l;
            if (cur_time_l - elapsed_time_l >= TOKEN_VALID_TIME) { // token expired, remove expired token, every user can only has 1 token
                System.out.println("ERROR: TOKEN EXPIRED. REQUEST NEW TOKEN AND RETRY.");
                String username = m_token_user.get(token);
                m_token_user.remove(token);
                return username;
            } else { // token valid, check if user is in role
                return "";
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
        return "exception";
    }

    public boolean tokenExists(String token) {
        return m_token_user.containsKey(token);
    }

    public String getNameFromToken(String token) {
        return m_token_user.get(token);
    }
}

