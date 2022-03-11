package com.hsbc.authService;

import org.springframework.stereotype.Service;
import java.util.ArrayList;

@Service
public class AuthInterface {
    private static UserGroup users;

    static {
        users = new UserGroup();
    }

    private static RoleGroup roles;

    static {
        roles = new RoleGroup();
    }

    private static TokenGroup tokens;

    static {
        tokens = new TokenGroup();
    }

    /**
     * create and store username and password in memory, password is encrypted by AES
     * @param username
     * @param password
     * @return
     */
    public static boolean createUser(String username, String password) {
        return users.createUser(username, password);
    };

    /**
     * remove all user traces from database, including username, password, role, and token
     * @param username
     * @return
     */
    public static boolean removeUser(String username) {
        // when a user is removed the corresponding tokens and the role held should also be removed
        String token = users.getToken(username);
        tokens.removeToken(token);
        roles.removeUserFromAllRoles(username);
        users.removeUser(username);
        return true;
    }

    /**
     *
     * @param role function to create new role and store in memory. Each role is unique, multiple creation of the same
     *             role will not change role database.
     * @return true if role creation is successful
     */
    public static boolean createRole(String role) {
        return roles.createRole(role);
    }

    /**
     *
     * @param role
     * @return
     */
    public static boolean removeRole(String role) {
        return roles.removeRole(role);
    }

    /**
     *
     * @param username
     * @param role
     * @return
     */
    public static boolean assignRole2User(String username, String role) {
        if (users.userExists(username) == false) {
            return false;
        } else {
            return roles.assignRole2User(username, role);
        }
    }

    /**
     * Verify username and passowrd, if valid, return token associated with the current time and user
     * @param username
     * @param password
     * @return
     */
    public static String authenticate(String username, String password) {
        if (users.userExists(username) == false) {
            return "ERROR: USER NOT CREATED";
        } else {
            // verify user password
            if(users.verifyPassword(username, password) == false) {
                return "ERROR: INCORRECT PASSWORD";
            } else {
                // remove token if username has a token, and store a new one
                String old_token = users.removeToken(username);
                if (old_token != "") {
                    tokens.removeToken(old_token);
                }
                String new_token = tokens.authenticate(username);
                users.createToken(username, new_token);
                return new_token;
            }
        }
    }

    /**
     * remove a token
     * @param token
     */
    public static void invalidate(String token) {
        String username = tokens.removeToken(token);
        if (username != "") {
            users.removeToken(username);
        }
    }

    /**
     * Extract user info from valid tokens (not expired), check if user in role
     * @param token
     * @param role
     * @return true if user token belongs to role
     */
    public static boolean checkRole(String token, String role) {
        if (tokens.tokenExists(token) == false) {
            return false;
        } else {
            String username = tokens.isTokenValid(token);
            if(username != "") {
                users.removeToken(username);
                System.out.println("ERROR: TOKEN EXPIRED, WAS REMOVED");
                return false;
            } else {
                username = tokens.getNameFromToken(token);
                if (roles.roleExists(role) == false) {
                    return false;
                } else {
                    return roles.checkRole(username, role);
                }
            }
        }

    }

    /**
     * extract user info from a valid token, iterate through all roles to check if the username belongs to role, store
     * role key in a list
     * @param token
     * @return list containing all roles belonging to the user, extracted from a valid token
     */
    public static ArrayList<String> getAllRoles(String token) {
        ArrayList<String> all_roles = new ArrayList<>();
        if (tokens.tokenExists(token) == false) {
            return all_roles;
        } else {
            String username = tokens.isTokenValid(token);
            if(username != "") {
                users.removeToken(username);
                System.out.println("ERROR: TOKEN EXPIRED, WAS REMOVED");
                return all_roles;
            } else {
                username = tokens.getNameFromToken(token);
                all_roles = roles.getAllRoles(username);
                return all_roles;
            }
        }
    }


}
