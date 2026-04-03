package com.passwordless.auth.repository;

import com.passwordless.auth.model.Credential;
import com.passwordless.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

/**
 * JPA repository interface for WebAuthn credential data access operations.
 * Provides CRUD operations and query methods for managing user authentication
 * credentials in the passwordless authentication system.
 */
@Repository
public interface JpaCredentialRepository extends JpaRepository<Credential, Long> {
    
    /**
     * Retrieves all credentials associated with a specific user.
     * Used during authentication to find registered authenticators
     * and for user credential management operations.
     * 
     * @param user User to find credentials for
     * @return List of credentials registered by the user
     */
    List<Credential> findByUser(User user);
    
    /**
     * Finds a credential by its unique credential ID.
     * Used during WebAuthn authentication assertion to locate
     * the specific credential being used for verification.
     * 
     * @param credentialId The credential ID to search for
     * @return Optional containing the credential if found, empty otherwise
     */
    Optional<Credential> findByCredentialId(String credentialId);
} 