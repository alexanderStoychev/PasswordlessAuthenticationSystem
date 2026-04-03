package com.passwordless.auth.controller;

import com.passwordless.auth.model.User;
import com.passwordless.auth.repository.UserRepository;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.passwordless.auth.service.WebAuthnService;
import com.passwordless.auth.service.LoginService;
import com.passwordless.auth.dto.LoginRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.*;

/**
 * REST controller handling WebAuthn registration and authentication endpoints.
 * Provides biometric authentication capabilities with contextual security analysis.
 */
@RestController
@RequestMapping("/api/webauthn")
public class WebAuthnController {

    @Autowired
    private WebAuthnService webAuthnService;
    
    @Autowired
    private LoginService loginService;

    @Autowired
    private UserRepository userRepository;

    /**
     * Generates WebAuthn registration options for new user enrollment.
     * 
     * @param username User's chosen username
     * @param displayName User's display name for the credential
     * @return WebAuthn credential creation options
     */
    @PostMapping("/register/options")
    public ResponseEntity<PublicKeyCredentialCreationOptions> getRegistrationOptions(
            @RequestParam String username,
            @RequestParam String displayName) {
        return ResponseEntity.ok(webAuthnService.getRegistrationOptions(username, displayName));
    }

    /**
     * Completes the WebAuthn registration process by verifying the credential.
     * 
     * @param responseJson Client's credential creation response
     * @param username Username associated with the registration
     * @return Success response or error details
     */
    @PostMapping("/register")
    public ResponseEntity<Void> register(
            @RequestBody String responseJson,
            @RequestParam String username) throws IOException {
        webAuthnService.finishRegistration(responseJson, username);
        return ResponseEntity.ok().build();
    }

    /**
     * Generates WebAuthn authentication options for existing users.
     * 
     * @param username Username to authenticate
     * @return WebAuthn credential request options
     */

     @PostMapping("/authenticate/options")
    public ResponseEntity<PublicKeyCredentialRequestOptions> getAuthenticationOptions(
            @RequestParam String username) {
        return ResponseEntity.ok(webAuthnService.getAuthenticationOptions(username));
    }

     /*
    @PostMapping("/authenticate/options")
    public ResponseEntity<PublicKeyCredentialRequestOptions> getAuthenticationOptions(
            @RequestParam String username) {
        long start = System.nanoTime();
        try {
            PublicKeyCredentialRequestOptions options = webAuthnService.getAuthenticationOptions(username);
            return ResponseEntity.ok(options);
        } catch (Exception e) {
            // Optionally handle exceptions (e.g., user not found)
            return ResponseEntity.badRequest().build();
        } finally {
            long elapsed = (System.nanoTime() - start) / 1_000_000; // ms
            long minResponseTime = 150; // ms, adjust as needed
            if (elapsed < minResponseTime) {
                try {
                    Thread.sleep(minResponseTime - elapsed);
                } catch (InterruptedException ignored) {}
            }
        }
    }
*/

    /**
     * Completes WebAuthn authentication with contextual security analysis.
     * Performs biometric verification and evaluates login context for suspicious patterns.
     * 
     * @param responseJson Client's authentication response
     * @param username Username being authenticated
     * @param request HTTP request for extracting contextual metadata
     * @return Authentication result with security evaluation
     */
    @PostMapping("/authenticate")
    public ResponseEntity<Map<String, Object>> authenticate(
            @RequestBody String responseJson,
            @RequestParam String username,
            HttpServletRequest request) throws IOException {
        
        try {
            // Skip WebAuthn verification for test trigger users
            if (!username.startsWith("trigger_")) {
                webAuthnService.finishAuthentication(responseJson, username);
            }

            Optional<User> user = userRepository.findByUsername(username);
            if (!user.isPresent()) {
                if (username.startsWith("trigger_")) {
                    // Create mock user for testing scenarios
                    User mock = new User();
                    mock.setId(System.currentTimeMillis());
                    mock.setUsername(username);
                    mock.setDisplayName("Test " + username);
                    userRepository.save(mock);
                } else {
                    Map<String, Object> response = new HashMap<>();
                    response.put("status", "error");
                    response.put("message", "User not found");
                    return ResponseEntity.badRequest().body(response);
                }
            }

            // Extract client metadata for contextual security analysis
            String ipAddress = getClientIpAddress(request);
            String userAgent = request.getHeader("User-Agent");
            
            // Perform contextual analysis on successful WebAuthn authentication
            LoginService.LoginResult result = loginService.logSuccessfulWebAuthnLogin(
                username, 
                ipAddress,
                userAgent
            );
            
            Map<String, Object> response = new HashMap<>();
            response.put("status", "ok");
            response.put("message", result.getMessage());
            response.put("evaluationResult", result.getEvaluationResult().toString());
            
            // Return appropriate HTTP status based on security evaluation
            if (result.getEvaluationResult() == com.passwordless.auth.model.LoginEvent.EvaluationResult.RED_FLAG) {
                return ResponseEntity.status(202).body(response); // 202 Accepted but flagged
            } else {
                return ResponseEntity.ok(response); // 200 OK
            }
            
        } catch (Exception e) {
            // Extract metadata for failed authentication logging
            String ipAddress = getClientIpAddress(request);
            String userAgent = request.getHeader("User-Agent");
            
            // Log failed authentication attempt with context
            loginService.logFailedWebAuthnAttempt(username, ipAddress, userAgent, e.getMessage());
            
            Map<String, Object> response = new HashMap<>();
            response.put("status", "error");
            response.put("message", "Authentication failed: " + e.getMessage());
            response.put("evaluationResult", "DENY");
            return ResponseEntity.status(401).body(response);
        }
    }
    
    /**
     * Traditional password-based login with contextual security analysis.
     * Provided as fallback authentication method alongside WebAuthn.
     * 
     * @param loginRequest Login credentials
     * @param request HTTP request for contextual metadata
     * @return Login result with security evaluation
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            @RequestBody LoginRequest loginRequest,
            HttpServletRequest request) {
        
        try {
            // Extract contextual metadata for analysis
            String ipAddress = getClientIpAddress(request);
            String userAgent = request.getHeader("User-Agent");
            
            // Authenticate user with contextual security analysis
            LoginService.LoginResult result = loginService.authenticateUser(
                loginRequest.getUsername(), 
                loginRequest.getPassword(),
                ipAddress,
                userAgent
            );
            
            Map<String, Object> response = new HashMap<>();
            
            if (result.isSuccess()) {
                response.put("status", "ok");
                response.put("message", result.getMessage());
                response.put("evaluationResult", result.getEvaluationResult().toString());
                
                // Return status based on security evaluation
                if (result.getEvaluationResult() == com.passwordless.auth.model.LoginEvent.EvaluationResult.RED_FLAG) {
                    return ResponseEntity.status(202).body(response); // 202 Accepted but flagged
                } else {
                    return ResponseEntity.ok(response); // 200 OK
                }
            } else {
                response.put("status", "error");
                response.put("message", result.getMessage());
                response.put("evaluationResult", result.getEvaluationResult().toString());
                return ResponseEntity.status(401).body(response);
            }
            
        } catch (Exception e) {
            Map<String, Object> response = new HashMap<>();
            response.put("status", "error");
            response.put("message", "Login failed: " + e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }
    
    /**
     * Extracts the client's real IP address from the HTTP request.
     * Handles common proxy headers and load balancer configurations.
     * 
     * @param request HTTP servlet request
     * @return Client's IP address
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }
    
    /**
     * Debug endpoint to inspect stored credentials for a user.
     * Used for troubleshooting WebAuthn registration and authentication issues.
     * 
     * @param username Username to inspect
     * @return Debug information about user's credentials
     */
    @GetMapping("/debug/credentials/{username}")
    public ResponseEntity<Map<String, Object>> getCredentials(@PathVariable String username) {
        try {
            Map<String, Object> response = webAuthnService.getCredentialsDebugInfo(username);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }
} 