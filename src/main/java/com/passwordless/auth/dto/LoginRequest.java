package com.passwordless.auth.dto;

/**
 * Data Transfer Object for traditional username/password login requests.
 * Used as a fallback authentication method alongside WebAuthn biometric authentication.
 */
public class LoginRequest {
    /** User's login name */
    private String username;
    
    /** User's password (in production, would be hashed) */
    private String password;
    
    /** Default constructor for JSON deserialization */
    public LoginRequest() {}
    
    /**
     * Constructor for creating login requests programmatically.
     * 
     * @param username User's login name
     * @param password User's password
     */
    public LoginRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }
    
    // Getters and Setters
    public String getUsername() { 
        return username; 
    }
    
    public void setUsername(String username) { 
        this.username = username; 
    }
    
    public String getPassword() { 
        return password; 
    }
    
    public void setPassword(String password) { 
        this.password = password; 
    }
} 