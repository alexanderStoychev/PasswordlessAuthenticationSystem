package com.passwordless.auth.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * JPA entity representing a user login attempt with contextual security analysis.
 * Stores comprehensive metadata about each authentication event for security monitoring,
 * threat detection, and audit purposes.
 */
@Entity
@Table(name = "login_events")
public class LoginEvent {
    
    /** Unique identifier for this login event */
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;
    
    /** User account associated with this login attempt */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
    
    /** Timestamp when the login attempt occurred */
    @Column(nullable = false)
    private LocalDateTime timestamp;
    
    /** IP address from which the login attempt originated */
    @Column(nullable = false)
    private String ipAddress;
    
    /** Browser user agent string for device fingerprinting */
    @Column(nullable = false, length = 1000)
    private String userAgent;
    
    /** Country resolved from IP address for geographic analysis */
    @Column
    private String country;
    
    /** Security evaluation result from contextual analysis */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private EvaluationResult evaluationResult;
    
    /** JSON string containing list of security rules that were triggered */
    @Column(columnDefinition = "TEXT")
    private String triggeredRules;
    
    /** Default constructor for JPA */
    public LoginEvent() {}
    
    /**
     * Full constructor for creating login events with all metadata.
     * 
     * @param user The user account attempting login
     * @param timestamp When the login attempt occurred
     * @param ipAddress Source IP address
     * @param userAgent Browser user agent string
     * @param country Geographic location from IP
     * @param evaluationResult Security analysis result
     * @param triggeredRules JSON string of triggered security rules
     */
    public LoginEvent(User user, LocalDateTime timestamp, String ipAddress, String userAgent, 
                     String country, EvaluationResult evaluationResult, String triggeredRules) {
        this.user = user;
        this.timestamp = timestamp;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.country = country;
        this.evaluationResult = evaluationResult;
        this.triggeredRules = triggeredRules;
    }
    
    /**
     * Convenience constructor that automatically sets timestamp to current time.
     * Useful for creating login events in real-time scenarios and experiments.
     * 
     * @param user The user account attempting login
     * @param ipAddress Source IP address
     * @param userAgent Browser user agent string
     * @param country Geographic location from IP
     * @param evaluationResult Security analysis result
     * @param triggeredRules JSON string of triggered security rules
     */
    public LoginEvent(User user, String ipAddress, String userAgent, String country, 
                     EvaluationResult evaluationResult, String triggeredRules) {
        this.user = user;
        this.timestamp = LocalDateTime.now();
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.country = country;
        this.evaluationResult = evaluationResult;
        this.triggeredRules = triggeredRules;
    }
    
    public UUID getId() { 
        return id; 
    }
    
    public void setId(UUID id) { 
        this.id = id; 
    }
    
    public User getUser() {
        return user;
    }
    
    public void setUser(User user) {
        this.user = user;
    }
    
    public LocalDateTime getTimestamp() { 
        return timestamp; 
    }
    
    public void setTimestamp(LocalDateTime timestamp) { 
        this.timestamp = timestamp; 
    }
    
    public String getIpAddress() { 
        return ipAddress; 
    }
    
    public void setIpAddress(String ipAddress) { 
        this.ipAddress = ipAddress; 
    }
    
    public String getUserAgent() { 
        return userAgent; 
    }
    
    public void setUserAgent(String userAgent) { 
        this.userAgent = userAgent; 
    }
    
    public String getCountry() { 
        return country; 
    }
    
    public void setCountry(String country) { 
        this.country = country; 
    }
    
    public EvaluationResult getEvaluationResult() {
        return evaluationResult;
    }
    
    public void setEvaluationResult(EvaluationResult evaluationResult) {
        this.evaluationResult = evaluationResult;
    }
    
    public String getTriggeredRules() {
        return triggeredRules;
    }
    
    public void setTriggeredRules(String triggeredRules) {
        this.triggeredRules = triggeredRules;
    }
    
    /**
     * Enumeration of possible security evaluation results for login attempts.
     * Used by the contextual analysis system to categorize risk levels.
     */
    public enum EvaluationResult {
        /** Login is approved - no security concerns detected */
        ALLOW,
        
        /** Login is approved but flagged for review - moderate risk indicators */
        RED_FLAG,
        
        /** Login is denied - high risk indicators detected */
        DENY
    }
} 