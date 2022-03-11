import org.junit.jupiter.api.Test;
import com.hsbc.authService.AuthInterface;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
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
     * Check if token expiration is detected. A false return with
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
            // Wait too looooong, time was set shorter for quick test :)
            Thread.sleep(2*60*60*1000 + 1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        assertFalse(AuthInterface.checkRole(token, "admin"));
        assertFalse(AuthInterface.checkRole(token2, "user"));
    }







}
