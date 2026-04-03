package com.passwordless.auth.service;

import com.passwordless.auth.model.LoginEvent;
import com.passwordless.auth.model.User;
import com.passwordless.auth.repository.LoginEventRepository;
import com.passwordless.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

/**
 * Service responsible for authentication logic and security event logging.
 * Handles both traditional password and WebAuthn authentication with contextual analysis.
 */
@Service
public class LoginService {
    
    private static final Logger logger = LoggerFactory.getLogger(LoginService.class);
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private LoginEventRepository loginEventRepository;
    
    @Autowired
    private GeoIpService geoIpService;
    
    @Autowired
    private ContextualAnalysisService contextualAnalysisService;
    
    /**
     * Authenticates a user with password and performs contextual security analysis.
     * 
     * @param username User's login name
     * @param password User's password (currently mocked for demo purposes)
     * @param ipAddress Client's IP address for analysis
     * @param userAgent Client's browser user agent
     * @return Authentication result with security evaluation
     */
    public LoginResult authenticateUser(String username, String password, String ipAddress, String userAgent) {
        Optional<User> userOpt = userRepository.findByUsername(username);
        
        if (userOpt.isEmpty()) {
            logFailedLoginAttempt(username, ipAddress, userAgent, "user_not_found");
            return new LoginResult(false, LoginEvent.EvaluationResult.DENY, "User not found");
        }
        
        User user = userOpt.get();
        LocalDateTime timestamp = LocalDateTime.now(ZoneOffset.UTC);
        
        // Analyze login context for suspicious patterns
        ContextualAnalysisService.LoginAnalysisResult analysis = 
            contextualAnalysisService.analyzeLoginAttempt(user, ipAddress, userAgent, timestamp);
        
        // Mock authentication - in production, verify password hash
        boolean isValidCredentials = true;
        
        if (!isValidCredentials) {
            logLoginEvent(user, ipAddress, userAgent, LoginEvent.EvaluationResult.DENY, analysis.getTriggeredRules());
            return new LoginResult(false, LoginEvent.EvaluationResult.DENY, "Invalid credentials");
        }
        
        // Deny access if contextual analysis suggests high risk
        if (analysis.getEvaluationResult() == LoginEvent.EvaluationResult.DENY) {
            logLoginEvent(user, ipAddress, userAgent, LoginEvent.EvaluationResult.DENY, analysis.getTriggeredRules());
            return new LoginResult(false, LoginEvent.EvaluationResult.DENY, "Access denied due to security concerns");
        }
        
        // Log successful authentication with security evaluation
        logLoginEvent(user, ipAddress, userAgent, analysis.getEvaluationResult(), analysis.getTriggeredRules());
        
        String message = analysis.getEvaluationResult() == LoginEvent.EvaluationResult.RED_FLAG 
            ? "Login successful but flagged for review" 
            : "Login successful";
            
        return new LoginResult(true, analysis.getEvaluationResult(), message);
    }
    
    /**
     * Records a login event with contextual metadata and security evaluation.
     * 
     * @param user The authenticated user
     * @param ipAddress Client's IP address
     * @param userAgent Client's browser user agent
     * @param evaluationResult Security analysis result
     * @param triggeredRules List of security rules that were triggered
     */
    private void logLoginEvent(User user, String ipAddress, String userAgent, 
                              LoginEvent.EvaluationResult evaluationResult, 
                              java.util.List<String> triggeredRules) {
        try {
            // Resolve geographic location from IP address
            String country = geoIpService.getCountryByIp(ipAddress);
            
            // Serialize triggered security rules for storage
            String triggeredRulesJson = contextualAnalysisService.convertTriggeredRulesToJson(triggeredRules);
            
            // Create comprehensive login event record
            LoginEvent loginEvent = new LoginEvent(
                user,
                LocalDateTime.now(ZoneOffset.UTC),
                ipAddress,
                userAgent,
                country,
                evaluationResult,
                triggeredRulesJson
            );
            
            // Persist event to database
            loginEventRepository.save(loginEvent);
            
            logger.info("Login event logged for user: {} from IP: {} ({}) - Result: {} - Rules: {}", 
                       user.getUsername(), ipAddress, country, evaluationResult, triggeredRules);
            
        } catch (Exception e) {
            logger.error("Failed to log login event for user: {}", user.getUsername(), e);
        }
    }
    
    /**
     * Logs failed authentication attempts for security monitoring.
     * 
     * @param username Attempted username
     * @param ipAddress Source IP address
     * @param userAgent Client's browser user agent
     * @param reason Reason for authentication failure
     */
    private void logFailedLoginAttempt(String username, String ipAddress, String userAgent, String reason) {
        try {
            String country = geoIpService.getCountryByIp(ipAddress);
            logger.warn("Failed login attempt for username: {} from IP: {} ({}) - Reason: {}", 
                       username, ipAddress, country, reason);
        } catch (Exception e) {
            logger.error("Failed to log failed login attempt for username: {}", username, e);
        }
    }
    
    /**
     * Processes successful WebAuthn authentication with contextual security analysis.
     * Includes special test triggers for demonstrating different security scenarios.
     * 
     * @param username Username that was authenticated
     * @param ipAddress Client's IP address
     * @param userAgent Client's browser user agent
     * @return Authentication result with security evaluation
     */
    public LoginResult logSuccessfulWebAuthnLogin(String username, String ipAddress, String userAgent) {
        try {
            User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

            // Handle special test trigger usernames for demonstration purposes
            switch (username) {
                case "trigger_new_ip":
                    return new LoginResult(true, LoginEvent.EvaluationResult.RED_FLAG, "Simulated trigger: new_ip");
                case "trigger_new_device":
                    return new LoginResult(true, LoginEvent.EvaluationResult.RED_FLAG, "Simulated trigger: new_device");
                case "trigger_unusual_time":
                    return new LoginResult(true, LoginEvent.EvaluationResult.RED_FLAG, "Simulated trigger: unusual_time");
                case "trigger_rapid_logins":
                    return new LoginResult(false, LoginEvent.EvaluationResult.DENY, "Simulated trigger: rapid_logins");
                case "trigger_failures":
                    return new LoginResult(false, LoginEvent.EvaluationResult.DENY, "Simulated trigger: recent_failures");
            }

            // Perform comprehensive contextual security analysis
            ContextualAnalysisService.LoginAnalysisResult analysis = 
                contextualAnalysisService.analyzeLoginAttempt(user, ipAddress, userAgent, LocalDateTime.now());
            
            // Record the successful WebAuthn authentication event
            logLoginEvent(user, ipAddress, userAgent, analysis.getEvaluationResult(), analysis.getTriggeredRules());
            
            String message = getMessageForResult(analysis.getEvaluationResult());
            return new LoginResult(true, analysis.getEvaluationResult(), message);
            
        } catch (Exception e) {
            logger.error("Error logging WebAuthn login for user: " + username, e);
            return new LoginResult(false, LoginEvent.EvaluationResult.DENY, "Login tracking failed");
        }
    }
    
    /**
     * Logs failed WebAuthn authentication attempts for security monitoring.
     * 
     * @param username Username that failed authentication
     * @param ipAddress Source IP address
     * @param userAgent Client's browser user agent
     * @param reason Reason for authentication failure
     */
    public void logFailedWebAuthnAttempt(String username, String ipAddress, String userAgent, String reason) {
        try {
            User user = userRepository.findByUsername(username).orElse(null);
            if (user != null) {
                logFailedLoginAttempt(username, ipAddress, userAgent, reason);
            }
        } catch (Exception e) {
            logger.error("Error logging failed WebAuthn attempt for user: " + username, e);
        }
    }
    
    /**
     * Generates user-friendly messages based on security evaluation results.
     * 
     * @param result The security evaluation result
     * @return Appropriate message for the evaluation result
     */
    private String getMessageForResult(LoginEvent.EvaluationResult result) {
        switch (result) {
            case ALLOW:
                return "Authentication successful";
            case RED_FLAG:
                return "Authentication successful but flagged for review";
            case DENY:
                return "Access denied due to security concerns";
            default:
                return "Authentication completed";
        }
    }
    
    /**
     * Data class representing the result of an authentication attempt.
     * Contains success status, security evaluation, and user message.
     */
    public static class LoginResult {
        private boolean success;
        private LoginEvent.EvaluationResult evaluationResult;
        private String message;
        
        public LoginResult(boolean success, LoginEvent.EvaluationResult evaluationResult, String message) {
            this.success = success;
            this.evaluationResult = evaluationResult;
            this.message = message;
        }
        
        public boolean isSuccess() { return success; }
        public LoginEvent.EvaluationResult getEvaluationResult() { return evaluationResult; }
        public String getMessage() { return message; }
    }
} 