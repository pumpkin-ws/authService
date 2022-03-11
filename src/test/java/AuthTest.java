import org.junit.jupiter.api.Test;
import com.hsbc.authService.AuthInterface;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AuthTest {
    /**
     *  Check if user addition and deletion can be properly handled
     */
    @Test
    void addAndDeleteUsers() {
        assertTrue(AuthInterface.createUser("Wilson", "123"));
        assertFalse(AuthInterface.createUser("Wilson", "123"));
        assertTrue(AuthInterface.createUser("Alice", "123"));
        assertTrue(AuthInterface.createUser("Bob", "234"));
        assertTrue(AuthInterface.removeUser("Wilson"));
    }

    /**
     * Check if role addition and removal can be properly handled
     */
    @Test
    void createAndRemoveRole() {
        assertTrue(AuthInterface.createRole("admin"));
        assertTrue(AuthInterface.createRole("user"));

        assertFalse(AuthInterface.createRole("admin"));
        assertTrue(AuthInterface.removeRole("admin"));
        assertFalse(AuthInterface.removeRole("admin"));
        assertFalse(AuthInterface.removeRole("player"));
    }

    /**
     * Check if users can be assigned roles properly
     */
    @Test
    void roleAssignment() {
        assertTrue(AuthInterface.createUser("Wilson", "123"));
        assertTrue(AuthInterface.createUser("Alice", "123"));
        assertTrue(AuthInterface.createUser("Bob", "234"));

        assertTrue(AuthInterface.createRole("admin"));
        assertTrue(AuthInterface.createRole("user"));

        assertTrue(AuthInterface.assignRole2User("Wilson", "admin"));
        assertTrue(AuthInterface.assignRole2User("Alice", "admin"));
        assertTrue(AuthInterface.assignRole2User("Wilson", "admin"));
        //Assign non-existent user
        assertFalse(AuthInterface.assignRole2User("Wison", "admin"));
        //Assign non-existent role
        assertFalse(AuthInterface.assignRole2User("Wilson", "ain"));

    }

    /**
     * Check getting authentication tokens and invalidating authenticating tokens
     */
    @Test
    void authenAndInvalidate() {
        assertTrue(AuthInterface.createUser("Wilson", "123"));
        assertTrue(AuthInterface.createUser("Alice", "123"));
        assertTrue(AuthInterface.createUser("Bob", "234"));

        assertTrue(AuthInterface.createRole("admin"));
        assertTrue(AuthInterface.createRole("user"));

        String token = AuthInterface.authenticate("Wilson", "123");
        System.out.println("The generated token is: " + token);
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        token = AuthInterface.authenticate("Wilson", "123");
        System.out.println("The generated token is: " + token);

        AuthInterface.invalidate(token);
    }

    /**
     * Check if user roles can be queried by user tokens
     */
    @Test
    void checkRole() {
        assertTrue(AuthInterface.createUser("Wilson", "123"));
        assertTrue(AuthInterface.createUser("Alice", "123"));
        assertTrue(AuthInterface.createUser("Bob", "234"));

        assertTrue(AuthInterface.createRole("admin"));
        assertTrue(AuthInterface.createRole("user"));

        assertTrue(AuthInterface.assignRole2User("Wilson", "admin"));
        assertTrue(AuthInterface.assignRole2User("Alice", "user"));
        assertTrue(AuthInterface.assignRole2User("Bob", "user"));

        String token = AuthInterface.authenticate("Wilson", "123");
        String token2 = AuthInterface.authenticate("Bob", "234");
        assertTrue(AuthInterface.checkRole(token, "admin"));
        assertTrue(AuthInterface.checkRole(token2, "user"));

    }

    /**
     * Check given a user token, if the algorithm is able to return all roles belonging to the user
     */
    @Test
    void getAllRole() {
        assertTrue(AuthInterface.createUser("Wilson", "123"));
        assertTrue(AuthInterface.createUser("Alice", "123"));
        assertTrue(AuthInterface.createUser("Bob", "234"));

        assertTrue(AuthInterface.createRole("admin"));
        assertTrue(AuthInterface.createRole("user"));
        assertTrue(AuthInterface.createRole("worker"));

        assertTrue(AuthInterface.assignRole2User("Wilson", "admin"));
        assertTrue(AuthInterface.assignRole2User("Alice", "user"));
        assertTrue(AuthInterface.assignRole2User("Bob", "user"));
        assertTrue(AuthInterface.assignRole2User("Wilson", "user"));
        assertTrue(AuthInterface.assignRole2User("Wilson", "worker"));
        String token = AuthInterface.authenticate("Alice", "123");
        String token2 = AuthInterface.authenticate("Wilson", "123");
        System.out.println(AuthInterface.getAllRoles(token));
        System.out.println(AuthInterface.getAllRoles(token2));
    }

    /**
     * Check if token expiration is detected. checkRole and getAllRoles will return false if the time of token expires
     */
    @Test
    void tokenExpiration() {
        assertTrue(AuthInterface.createUser("Wilson", "123"));
        assertTrue(AuthInterface.createUser("Alice", "123"));
        assertTrue(AuthInterface.createUser("Bob", "234"));

        assertTrue(AuthInterface.createRole("admin"));
        assertTrue(AuthInterface.createRole("user"));

        assertTrue(AuthInterface.assignRole2User("Wilson", "admin"));
        assertTrue(AuthInterface.assignRole2User("Alice", "user"));
        assertTrue(AuthInterface.assignRole2User("Bob", "user"));

        String token = AuthInterface.authenticate("Wilson", "123");
        String token2 = AuthInterface.authenticate("Bob", "234");

        try {
            // Waited too long, time was set shorter for quick test :)
            Thread.sleep(2*60*60*1000 + 1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        assertFalse(AuthInterface.checkRole(token, "admin"));
        assertFalse(AuthInterface.checkRole(token2, "user"));
    }







}
