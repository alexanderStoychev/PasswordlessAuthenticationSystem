package com.passwordless.auth.repository;

import com.passwordless.auth.model.Credential;
import com.passwordless.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Primary repository interface for WebAuthn credential management.
 * Extends JPA repository to provide standard CRUD operations and
 * custom query methods for authenticator credential storage.
 * 
 * This interface serves as the main data access layer for credential
 * operations in the passwordless authentication system.
 */
@Repository
public interface CredentialRepository extends JpaRepository<Credential, Long> {
    
    /**
     * Retrieves all credentials registered by a specific user.
     * 
     * @param user User whose credentials to retrieve
     * @return List of credentials associated with the user
     */
    List<Credential> findByUser(User user);
    
    /**
     * Finds a credential by its unique WebAuthn credential ID.
     * 
     * @param credentialId The credential ID to search for
     * @return Optional containing the credential if found
     */
    Optional<Credential> findByCredentialId(String credentialId);
} 