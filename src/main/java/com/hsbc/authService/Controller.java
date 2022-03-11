package com.hsbc.authService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@RestController
public class Controller {

    @Autowired
    private AuthInterface authInterface;

    /**
     * Reauest to create user, with username and password passed in as POST request
     * @param request contains username and password pair
     * @return
     */
    @RequestMapping(method = RequestMethod.POST, value = "/createUser")
    public String createUser(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");
        if (authInterface.createUser(username, password)) {
            return "User created";
        }
        return "Failed to create";
    }

    /**
     * Request to remove user given the username, with username passed in as POST request
     * @param username
     * @return
     */
    @RequestMapping(method = RequestMethod.POST, value = "/removeUser")
    public String removeUser(@RequestBody String username) {
        if (authInterface.removeUser(username)) {
            return "User removed";
        }
        return "Failed to remove!";
    }

    /**
     * Request to create role, with name of role passed in as POST request
     * @param role
     * @return
     */
    @RequestMapping(method = RequestMethod.POST, value = "/createRole")
    public String createRole(@RequestBody String role) {
        if (authInterface.createRole(role)) {
            return "Role created";
        }
        return "Failed to create role!";
    }

    /**
     * Request to remove role, with name of role passed in a POST request
     * @param role
     * @return
     */
    @RequestMapping(method = RequestMethod.POST, value = "/removeRole")
    public String removeRole(@RequestBody String role) {
        if (authInterface.removeRole(role)) {
            return "Role removed";
        }
        return "Failed to remove role!";
    }

    /**
     * Request to assign role to user, with username and role passed in as POST request
     * @param request
     * @return
     */
    @RequestMapping(method = RequestMethod.POST, value = "/assignUserRole")
    public String assignUserRole(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String role = request.get("role");
        if (authInterface.assignRole2User(username, role)) {
            return "Role assigned";
        }
        return "Failed to assign";
    }

    /**
     * Request to get user token, with username and password passed in as POST request
     * @param request
     * @return
     */
    @RequestMapping(method = RequestMethod.POST, value = "/getUserToken")
    public String getUserToken(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");
        String authen_result = authInterface.authenticate(username, password);
        if (authen_result.contains("ERROR")){
            System.out.println("FAILED TO GENERATE USER TOKEN");
        }
        return authen_result;
    }

    /**
     * Request to invalidate token, with token passed in as POST request
     * @param token
     * @return
     */
    @RequestMapping(method = RequestMethod.POST, value = "/invalidateUserToken")
    public String invalidateToken(@RequestBody String token) {
        authInterface.invalidate(token);
        return "Token invalidated";
    }

    /**
     * Request to check if a user token has a certain role, with user token and role passed in as POST request
     * @param request
     * @return
     */
    @RequestMapping(method = RequestMethod.POST, value = "/checkRole")
    public String checkRole(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        String role = request.get("role");
        if(authInterface.checkRole(token, role)) {
            return "user token has role of " + role;
        }
        return "\"user token has role of \" + role;";
    }

    /**
     * Request to get all roles given a user token, with the user token passed in as POST request
     * @param token
     * @return return user roles, separated by comma
     */
    @RequestMapping(method = RequestMethod.POST, value = "/getAllRoles")
    public String getAllRoles(@RequestBody String token) {
        ArrayList<String> all_roles = new ArrayList<>();
        all_roles = authInterface.getAllRoles(token);
        String roles_str = new String();
        for(String s : all_roles) {
            roles_str  = roles_str + "," + s;
        }
        return roles_str;
    }



}
