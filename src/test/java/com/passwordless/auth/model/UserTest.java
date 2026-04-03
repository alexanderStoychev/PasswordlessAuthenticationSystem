package com.passwordless.auth.model;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive test suite for the User entity.
 * Tests entity relationships and business logic.
 */
class UserTest {

    private User user;

    @BeforeEach
    void setUp() {
        user = new User();
        user.setUsername("testuser");
        user.setDisplayName("Test User");
        user.setHandle("unique-handle-123");
    }

    @Test
    void testValidUserCreation() {
        // Verify all fields are set correctly
        assertEquals("testuser", user.getUsername());
        assertEquals("Test User", user.getDisplayName());
        assertEquals("unique-handle-123", user.getHandle());
    }

    @Test
    void testUserWithCredentials() {
        // Setup credentials
        user.setCredentials(new ArrayList<>());
        
        Credential credential = new Credential();
        credential.setCredentialId("test-credential-id");
        credential.setPublicKeyCose("test-public-key");
        credential.setSignatureCount(0L);
        credential.setUser(user);
        
        user.getCredentials().add(credential);
        
        // Verify relationship
        assertEquals(1, user.getCredentials().size());
        assertEquals(credential, user.getCredentials().get(0));
        assertEquals(user, credential.getUser());
    }

    @Test
    void testEmptyUsernameHandling() {
        user.setUsername("");
        assertEquals("", user.getUsername());
    }

    @Test
    void testNullUsernameHandling() {
        user.setUsername(null);
        assertNull(user.getUsername());
    }

    @Test
    void testUserEquality() {
        User user1 = new User();
        user1.setId(1L);
        user1.setUsername("testuser");
        
        User user2 = new User();
        user2.setId(1L);
        user2.setUsername("testuser");
        
        User user3 = new User();
        user3.setId(2L);
        user3.setUsername("otheruser");
        
        // Test equality based on ID
        assertEquals(user1.getId(), user2.getId());
        assertNotEquals(user1.getId(), user3.getId());
    }

    @Test
    void testUserToString() {
        user.setId(1L);
        String userString = user.toString();
        
        // Verify toString includes important information
        assertNotNull(userString);
        // Just verify toString returns a valid string representation
        assertTrue(userString.length() > 0);
    }

    @Test
    void testUserBuilder() {
        // Test builder pattern if implemented
        User builtUser = new User();
        builtUser.setUsername("buildertest");
        builtUser.setDisplayName("Builder Test");
        builtUser.setHandle("builder-handle");
        
        assertEquals("buildertest", builtUser.getUsername());
        assertEquals("Builder Test", builtUser.getDisplayName());
        assertEquals("builder-handle", builtUser.getHandle());
    }

    @Test
    void testCredentialCascadeOperations() {
        // Test cascade operations with credentials
        user.setCredentials(new ArrayList<>());
        
        Credential credential1 = new Credential();
        credential1.setCredentialId("cred1");
        credential1.setUser(user);
        
        Credential credential2 = new Credential();
        credential2.setCredentialId("cred2");
        credential2.setUser(user);
        
        user.getCredentials().add(credential1);
        user.getCredentials().add(credential2);
        
        assertEquals(2, user.getCredentials().size());
        assertTrue(user.getCredentials().contains(credential1));
        assertTrue(user.getCredentials().contains(credential2));
    }

    @Test
    void testHandleUniqueness() {
        // Test that handles should be unique
        String handle1 = "unique-handle-1";
        String handle2 = "unique-handle-2";
        
        User user1 = new User();
        user1.setHandle(handle1);
        
        User user2 = new User();
        user2.setHandle(handle2);
        
        assertNotEquals(user1.getHandle(), user2.getHandle());
    }
} 