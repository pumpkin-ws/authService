package com.hsbc.authService;

import java.util.*;

/**
 * Role group contains the data structure that holds all the roles and users contained in each role
 */
public class RoleGroup {
    private HashSet<String> m_role;
    private HashMap<String, HashSet<String>> m_role_user; // a role can have many users

    RoleGroup() {
        m_role = new HashSet<>();
        m_role_user = new HashMap<>();
    }

    public boolean createRole(String role) {
        if (m_role.contains(role) == true) {
            System.out.println("ERROR: ROLE ALREADY EXISTS");
            return false;
        } else {
            m_role.add(role);
            m_role_user.put(role, new HashSet<String>());
            System.out.println("Number of role: " + m_role.size());
            System.out.println("Number of role-user: " + m_role_user.size());
            System.out.println("---------------------------------------------");
            return true;
        }
    }

    public boolean removeRole(String role) {
        if (m_role.contains(role) == false) {
            System.out.println("ERROR: ROLE NOT IN LIST");
            return false;
        } else {
            m_role.remove(role);
            // if a role is deleted, then roles in the user-role pair should be removed as well
            m_role_user.remove(role);

            System.out.println("Number of role: " + m_role.size());
            System.out.println("Number of role-user: " + m_role_user.size());
            System.out.println("---------------------------------------------");
            return true;
        }
    }

    public boolean assignRole2User(String user, String role) {
        if (m_role.contains(role) == true) {
            m_role_user.get(role).add(user); // add user to the role TODO: need to check get and add
            System.out.println(role + ":" + m_role_user.get(role));
            return true;
        } else {
            System.out.println("Role is not created yet. Create role first then user can be assigned.");
            return false;
        }
    }
    public boolean removeUserRole(String user, String role) {
        if (m_role.contains(role) == true) {
            if (m_role_user.get(role).contains(user) == true) {
                m_role_user.get(role).remove(user);
                return true;
            } else {
                System.out.println("ERROR: ROLE DOES NOT CONTAIN USER");
                return false;
            }
        } else {
            System.out.println("ERROR: ROLE DOES NOT EXIST");
            return false;
        }
    }
    public boolean roleExists(String role) {
        return m_role.contains(role);
    }
    public boolean checkRole(String username, String role) {
        return m_role_user.get(role).contains(username);
    }
    public ArrayList<String> getAllRoles(String username) {
        ArrayList<String> all_roles = new ArrayList<>();
        Iterator<HashMap.Entry<String, HashSet<String>>> it = m_role_user.entrySet().iterator();
        while(it.hasNext()) {
            HashMap.Entry<String, HashSet<String>> pair = it.next();
            if (pair.getValue().contains(username) == true) {
                all_roles.add(pair.getKey());
            }
        }
        return all_roles;
    }
    public void removeUserFromAllRoles(String username) {
        Iterator<HashMap.Entry<String, HashSet<String>>> it = m_role_user.entrySet().iterator();
        while(it.hasNext()) {
            HashMap.Entry<String, HashSet<String>> pair = it.next();
            if (pair.getValue().contains("user") == true) {
                pair.getValue().remove(username);
            }
        }
    }


}