package com.passwordless.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Main Spring Boot application class for the Passwordless Authentication system.
 * Demonstrates WebAuthn biometric authentication with contextual security analysis.
 * 
 * This application provides:
 * - WebAuthn-based biometric authentication
 * - Contextual security analysis for login attempts
 * - Machine learning-based threat detection
 * - Security event logging and feedback systems
 */
@SpringBootApplication
public class PasswordlessAuthApplication {
    /**
     * Application entry point.
     * 
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        SpringApplication.run(PasswordlessAuthApplication.class, args);
    }
}