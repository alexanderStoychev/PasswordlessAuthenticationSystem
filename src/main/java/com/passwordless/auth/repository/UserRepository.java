package com.passwordless.auth.repository;

import com.passwordless.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository interface for User entity data access operations.
 * Provides CRUD operations and custom query methods for user management
 * in the passwordless authentication system.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    /**
     * Finds a user by their unique username.
     * Used for user lookup during authentication and profile operations.
     * 
     * @param username The username to search for
     * @return Optional containing the user if found, empty otherwise
     */
    Optional<User> findByUsername(String username);
    
    /**
     * Finds a user by their WebAuthn handle (user ID).
     * Used during WebAuthn authentication to resolve user identity
     * from the credential assertion response.
     * 
     * @param handle The WebAuthn user handle (base64url encoded user ID)
     * @return Optional containing the user if found, empty otherwise
     */
    Optional<User> findByHandle(String handle);
} 