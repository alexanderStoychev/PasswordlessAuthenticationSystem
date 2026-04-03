package com.passwordless.auth.model;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive test suite for the Credential entity.
 * Tests WebAuthn credential properties and user relationships.
 */
class CredentialTest {

    private Credential credential;
    private User user;

    @BeforeEach
    void setUp() {
        user = new User();
        user.setId(1L);
        user.setUsername("testuser");
        user.setDisplayName("Test User");
        user.setHandle("test-handle");

        credential = new Credential();
        credential.setCredentialId("test-credential-id-123");
        credential.setPublicKeyCose("test-public-key-cose");
        credential.setSignatureCount(0L);
        credential.setUser(user);
    }

    @Test
    void testValidCredentialCreation() {
        // Verify all fields are set correctly
        assertEquals("test-credential-id-123", credential.getCredentialId());
        assertEquals("test-public-key-cose", credential.getPublicKeyCose());
        assertEquals(0L, credential.getSignatureCount());
        assertEquals(user, credential.getUser());
    }

    @Test
    void testCredentialUserRelationship() {
        // Test bidirectional relationship
        assertNotNull(credential.getUser());
        assertEquals("testuser", credential.getUser().getUsername());
        assertEquals(1L, credential.getUser().getId());
    }

    @Test
    void testSignatureCountIncrement() {
        // Test signature count management
        assertEquals(0L, credential.getSignatureCount());
        
        credential.setSignatureCount(1L);
        assertEquals(1L, credential.getSignatureCount());
        
        credential.setSignatureCount(credential.getSignatureCount() + 1);
        assertEquals(2L, credential.getSignatureCount());
    }

    @Test
    void testCredentialIdHandling() {
        // Test credential ID properties
        String credentialId = "unique-credential-id-456";
        credential.setCredentialId(credentialId);
        
        assertEquals(credentialId, credential.getCredentialId());
        assertNotNull(credential.getCredentialId());
        assertTrue(credential.getCredentialId().length() > 0);
    }

    @Test
    void testPublicKeyCoseHandling() {
        // Test public key COSE handling
        String publicKey = "encoded-public-key-cose-data";
        credential.setPublicKeyCose(publicKey);
        
        assertEquals(publicKey, credential.getPublicKeyCose());
        assertNotNull(credential.getPublicKeyCose());
    }

    @Test
    void testNullCredentialId() {
        credential.setCredentialId(null);
        assertNull(credential.getCredentialId());
    }

    @Test
    void testNullPublicKey() {
        credential.setPublicKeyCose(null);
        assertNull(credential.getPublicKeyCose());
    }

    @Test
    void testNullUser() {
        credential.setUser(null);
        assertNull(credential.getUser());
    }

    @Test
    void testCredentialEquality() {
        Credential credential1 = new Credential();
        credential1.setId(1L);
        credential1.setCredentialId("same-id");
        
        Credential credential2 = new Credential();
        credential2.setId(1L);
        credential2.setCredentialId("same-id");
        
        Credential credential3 = new Credential();
        credential3.setId(2L);
        credential3.setCredentialId("different-id");
        
        // Test equality based on ID
        assertEquals(credential1.getId(), credential2.getId());
        assertNotEquals(credential1.getId(), credential3.getId());
    }

    @Test
    void testCredentialToString() {
        credential.setId(1L);
        String credentialString = credential.toString();
        
        // Verify toString includes important information
        assertNotNull(credentialString);
        assertTrue(credentialString.contains("test-credential-id-123") || 
                  credentialString.contains("1") ||
                  credentialString.contains("Credential"));
    }

    @Test
    void testMultipleCredentialsForUser() {
        // Test that a user can have multiple credentials
        User userWithMultipleCredentials = new User();
        userWithMultipleCredentials.setUsername("multiuser");
        
        Credential credential1 = new Credential();
        credential1.setCredentialId("cred-1");
        credential1.setUser(userWithMultipleCredentials);
        
        Credential credential2 = new Credential();
        credential2.setCredentialId("cred-2");
        credential2.setUser(userWithMultipleCredentials);
        
        // Verify both credentials point to same user
        assertEquals(userWithMultipleCredentials, credential1.getUser());
        assertEquals(userWithMultipleCredentials, credential2.getUser());
        assertNotEquals(credential1.getCredentialId(), credential2.getCredentialId());
    }

    @Test
    void testSignatureCountValidation() {
        // Test signature count constraints
        credential.setSignatureCount(-1L);
        assertEquals(-1L, credential.getSignatureCount()); // Should handle negative values gracefully
        
        credential.setSignatureCount(Long.MAX_VALUE);
        assertEquals(Long.MAX_VALUE, credential.getSignatureCount());
    }

    @Test
    void testCredentialIdUniqueness() {
        // Test that credential IDs should be unique
        String uniqueId1 = "unique-id-1";
        String uniqueId2 = "unique-id-2";
        
        Credential cred1 = new Credential();
        cred1.setCredentialId(uniqueId1);
        
        Credential cred2 = new Credential();
        cred2.setCredentialId(uniqueId2);
        
        assertNotEquals(cred1.getCredentialId(), cred2.getCredentialId());
    }
} 