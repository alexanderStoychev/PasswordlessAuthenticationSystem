package com.passwordless.auth.service;

import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.exception.RegistrationFailedException;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.AssertionResult;
import com.passwordless.auth.model.User;
import com.passwordless.auth.model.Credential;
import com.passwordless.auth.repository.UserRepository;
import com.passwordless.auth.repository.JpaCredentialRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.HashMap;
import java.util.Collections;
import java.util.Random;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Page;

/**
 * Service class handling WebAuthn operations including registration and authentication.
 * Manages credential creation, storage, and verification using the Yubico WebAuthn library.
 */
@Service
public class WebAuthnService {

    @Autowired
    private RelyingParty relyingParty;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JpaCredentialRepository credentialRepository;
    
    // Thread-safe storage for pending WebAuthn operations
    private final Map<String, PublicKeyCredentialCreationOptions> pendingRegistrations = new ConcurrentHashMap<>();
    private final Map<String, com.yubico.webauthn.AssertionRequest> pendingAssertions = new ConcurrentHashMap<>();

    /**
     * Initiates WebAuthn registration process by generating credential creation options.
     * Creates or retrieves user record and prepares WebAuthn registration challenge.
     * 
     * @param username Unique username for the credential
     * @param displayName Human-readable display name
     * @return WebAuthn credential creation options for client
     */
    public PublicKeyCredentialCreationOptions getRegistrationOptions(String username, String displayName) {
        User user = userRepository.findByUsername(username)
            .orElseGet(() -> {
                User newUser = new User();
                newUser.setUsername(username);
                newUser.setDisplayName(displayName);
                newUser.setHandle(UUID.randomUUID().toString());
                return userRepository.save(newUser);
            });

        PublicKeyCredentialCreationOptions options = relyingParty.startRegistration(
            StartRegistrationOptions.builder()
                .user(UserIdentity.builder()
                    .name(user.getUsername())
                    .displayName(user.getDisplayName())
                    .id(new ByteArray(user.getHandle().getBytes()))
                    .build())
                .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                    .residentKey(ResidentKeyRequirement.PREFERRED)
                    .build())
                .build());
                
        // Store registration options for verification during completion
        pendingRegistrations.put(username, options);
        
        return options;
    }

    /**
     * Completes WebAuthn registration by verifying the credential and storing it.
     * Validates the client's credential creation response against the stored challenge.
     * 
     * @param responseJson JSON response from WebAuthn credential creation
     * @param username Username associated with the registration
     * @throws IOException If response parsing fails
     * @throws RuntimeException If registration verification fails
     */
    public void finishRegistration(String responseJson, String username) throws IOException {
        try {
            User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalStateException("User not found"));
                
            // Retrieve stored registration options for verification
            PublicKeyCredentialCreationOptions request = pendingRegistrations.get(username);
            if (request == null) {
                throw new IllegalStateException("No pending registration found for user: " + username);
            }

            System.out.println("Response JSON: " + responseJson);
            System.out.println("Username: " + username);
            
            try {
                PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> pkc =
                    PublicKeyCredential.parseRegistrationResponseJson(responseJson);
                
                // Verify credential creation response
                RegistrationResult result = relyingParty.finishRegistration(FinishRegistrationOptions.builder()
                    .request(request)
                    .response(pkc)
                    .build());

                // Store verified credential in database
                Credential credential = new Credential();
                credential.setUser(user);
                credential.setCredentialId(result.getKeyId().getId().getBase64());
                credential.setPublicKeyCose(result.getPublicKeyCose().getBase64());
                credential.setSignatureCount(result.getSignatureCount());

                credentialRepository.save(credential);
                
                // Clean up stored registration request
                pendingRegistrations.remove(username);
            } catch (Exception e) {
                System.err.println("Error parsing registration response: " + e.getMessage());
                e.printStackTrace();
                throw e;
            }
        } catch (RegistrationFailedException e) {
            System.err.println("Registration failed: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Registration failed", e);
        }
    }

    /**
     * Initiates WebAuthn authentication by generating credential request options.
     * Prepares authentication challenge for registered user credentials.
     * 
     * @param username Username to authenticate
     * @return WebAuthn credential request options for client
     * @throws IllegalStateException If user is not found
     */
    /* 
    public PublicKeyCredentialRequestOptions getAuthenticationOptions(String username) {
        // Verify user exists before creating authentication challenge
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new IllegalStateException("User not found"));
        
        // Create authentication request with user's registered credentials
        com.yubico.webauthn.AssertionRequest assertionRequest = relyingParty.startAssertion(
            StartAssertionOptions.builder()
                .username(username)
                .userHandle(new ByteArray(user.getHandle().getBytes()))
                .build());
                
        // Store assertion request for verification during completion
        pendingAssertions.put(username, assertionRequest);
        
        // Log authentication setup for debugging
        System.out.println("Authentication options prepared for user: " + username);
        System.out.println("User handle: " + user.getHandle());
        
        return assertionRequest.getPublicKeyCredentialRequestOptions();
    }
    */

    /* first attempt fake hardcoded user and credentials good solution but still has slight timing gap
    public PublicKeyCredentialRequestOptions getAuthenticationOptions(String username) {
        User user = userRepository.findByUsername(username)
            .orElse(null);

        if (user == null) {
            // Create dummy user
            user = new User();
            user.setUsername("dummy");
            user.setDisplayName("Dummy User");
            user.setHandle("dummy-handle");
        }

        // Use real or dummy credentials
        List<Credential> credentials;
        if ("dummy".equals(user.getUsername())) {
            // Create a dummy credential
            Credential dummyCredential = new Credential();
            dummyCredential.setCredentialId("dummy-credential-id");
            dummyCredential.setUser(user);
            dummyCredential.setPublicKeyCose("dummy-public-key");
            dummyCredential.setSignatureCount(0);
            credentials = List.of(dummyCredential);
        } else {
            credentials = credentialRepository.findByUser(user);
        }

        // Build assertion request as usual, using user
        com.yubico.webauthn.AssertionRequest assertionRequest = relyingParty.startAssertion(
            StartAssertionOptions.builder()
                .username(user.getUsername())
                .userHandle(new ByteArray(user.getHandle().getBytes()))
                .build());

        pendingAssertions.put(username, assertionRequest);

        return assertionRequest.getPublicKeyCredentialRequestOptions();
    }
*/

     /**
     * !!Final solution for timing gap!!
     * Initiates WebAuthn authentication by generating credential request options.
     * Prepares authentication challenge for registered user credentials.
     * 
     * Uses a random user and credentials to ensure that there is no timing gap
     * uses dummy user and credentials if user is not found
     * 
     * @param username Username to authenticate
     * @return WebAuthn credential request options for client
     * @throws IllegalStateException If user is not found
     */
    public PublicKeyCredentialRequestOptions getAuthenticationOptions(String username) {
        User user = userRepository.findByUsername(username).orElse(null);

        List<Credential> credentials;
        if (user == null) {
            // Get the total number of users
            long userCount = userRepository.count();
            if (userCount > 0) {
                // Pick a random user index
                int randomIndex = new Random().nextInt((int) userCount);
                // Fetch a random user using paging
                Page<User> userPage = userRepository.findAll(PageRequest.of(randomIndex, 1));
                User randomUser = userPage.getContent().get(0);
                // Fetch credentials for this random user
                credentials = credentialRepository.findByUser(randomUser);
            } else {
                credentials = Collections.emptyList();
            }

            // Use a dummy user object for the rest of the method
            user = new User();
            user.setUsername("dummy");
            user.setDisplayName("Dummy User");
            user.setHandle("dummy-handle");
        }

         // Build assertion request as usual, using user
        com.yubico.webauthn.AssertionRequest assertionRequest = relyingParty.startAssertion(
            StartAssertionOptions.builder()
                .username(user.getUsername())
                .userHandle(new ByteArray(user.getHandle().getBytes()))
                .build());

        pendingAssertions.put(username, assertionRequest);

        return assertionRequest.getPublicKeyCredentialRequestOptions();
    }

    /**
     * Completes WebAuthn authentication by verifying the credential assertion.
     * Validates the client's authentication response and updates signature counter.
     * 
     * @param responseJson JSON response from WebAuthn authentication
     * @param username Username being authenticated
     * @throws IOException If response parsing fails
     * @throws RuntimeException If authentication verification fails
     */
    public void finishAuthentication(String responseJson, String username) throws IOException {
        try {
            // Retrieve stored assertion request for verification
            com.yubico.webauthn.AssertionRequest request = pendingAssertions.get(username);
            if (request == null) {
                throw new IllegalStateException("No pending authentication found for user: " + username);
            }
            
            System.out.println("Authentication response JSON: " + responseJson);
            System.out.println("Authentication username: " + username);
            
            try {
                PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> pkc =
                    PublicKeyCredential.parseAssertionResponseJson(responseJson);
                
                System.out.println("Credential ID: " + pkc.getId());
                System.out.println("Allowed credential IDs: " + request.getPublicKeyCredentialRequestOptions().getAllowCredentials());
                
                // Verify authentication response
                AssertionResult result = relyingParty.finishAssertion(FinishAssertionOptions.builder()
                    .request(request)
                    .response(pkc)
                    .build());

                if (result.isSuccess()) {
                    // Update signature counter for verified credential
                    String credentialId = result.getCredential().getCredentialId().getBase64();
                    Optional<Credential> credential = credentialRepository.findByCredentialId(credentialId);

                    credential.ifPresent(c -> {
                        c.setSignatureCount(result.getSignatureCount());
                        credentialRepository.save(c);
                    });
                    
                    // Clean up stored assertion request
                    pendingAssertions.remove(username);
                } else {
                    throw new RuntimeException("Authentication failed: verification was not successful");
                }
            } catch (Exception e) {
                System.err.println("Error parsing authentication response: " + e.getMessage());
                e.printStackTrace();
                throw e;
            }
        } catch (AssertionFailedException e) {
            System.err.println("Authentication failed: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Authentication failed", e);
        }
    }
    
    /**
     * Provides debug information about a user's stored credentials.
     * Used for troubleshooting registration and authentication issues.
     * 
     * @param username Username to inspect
     * @return Map containing credential debug information
     */
    public Map<String, Object> getCredentialsDebugInfo(String username) {
        Map<String, Object> response = new HashMap<>();
        
        try {
            Optional<User> user = userRepository.findByUsername(username);
            if (user.isPresent()) {
                response.put("userFound", true);
                response.put("userId", user.get().getId());
                response.put("userHandle", user.get().getHandle());
                
                List<Credential> credentials = credentialRepository.findByUser(user.get());
                response.put("credentialCount", credentials.size());
                response.put("credentials", credentials);
            } else {
                response.put("userFound", false);
                response.put("message", "User not found: " + username);
            }
        } catch (Exception e) {
            response.put("error", "Error retrieving credentials: " + e.getMessage());
        }
        
        return response;
    }
} 