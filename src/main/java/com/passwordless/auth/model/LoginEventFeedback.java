package com.passwordless.auth.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * JPA entity representing feedback on login event security evaluations.
 * Used for machine learning improvement and false positive/negative tracking.
 * Enables the contextual analysis system to learn from human judgment and incident data.
 */
@Entity
@Table(name = "login_event_feedback")
public class LoginEventFeedback {
    
    /** Unique identifier for this feedback entry */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;
    
    /** The login event that this feedback relates to */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "login_event_id", nullable = false)
    private LoginEvent loginEvent;
    
    /** Type of feedback indicating correctness of the original security evaluation */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private FeedbackType feedbackType;
    
    /** Source that provided this feedback for credibility weighting */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private FeedbackSource source;
    
    /** Identifier of the reviewer who provided feedback (null for automated feedback) */
    @Column(name = "reviewer_id")
    private String reviewerId;
    
    /** Additional comments or context about the feedback */
    @Column(columnDefinition = "TEXT")
    private String comments;
    
    /** When this feedback was provided */
    @Column(nullable = false)
    private LocalDateTime timestamp;

    /**
     * Enumeration of feedback types for machine learning training.
     * Indicates whether the original security evaluation was correct.
     */
    public enum FeedbackType {
        /** Security system correctly identified a threat - reinforce these patterns */
        TRUE_POSITIVE,
        
        /** Security system correctly allowed a legitimate login - maintain these thresholds */
        TRUE_NEGATIVE,
    }
    
    /**
     * Enumeration of feedback sources for weighting credibility.
     * Different sources have different reliability levels for machine learning.
     */
    public enum FeedbackSource {
        /** Manual review by trained security personnel - highest credibility */
        ADMIN_REVIEW,
        
        /** User reported false positive - moderate credibility, needs verification */
        USER_REPORT,
        
        /** System-generated feedback based on behavioral patterns - lower credibility */
        AUTOMATED_SYSTEM,
        
        /** Feedback from confirmed security incident investigation - highest credibility */
        INCIDENT_RESPONSE
    }
    
    /** Default constructor for JPA */
    public LoginEventFeedback() {}
    
    /**
     * Constructor for creating feedback entries.
     * Automatically sets timestamp to current time.
     * 
     * @param loginEvent The login event being evaluated
     * @param feedbackType Whether the original evaluation was correct
     * @param source Who or what provided this feedback
     * @param reviewerId Identifier of human reviewer (null for automated)
     */
    public LoginEventFeedback(LoginEvent loginEvent, FeedbackType feedbackType, 
                             FeedbackSource source, String reviewerId) {
        this.loginEvent = loginEvent;
        this.feedbackType = feedbackType;
        this.source = source;
        this.reviewerId = reviewerId;
        this.timestamp = LocalDateTime.now();
    }
    
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    
    public LoginEvent getLoginEvent() { return loginEvent; }
    public void setLoginEvent(LoginEvent loginEvent) { this.loginEvent = loginEvent; }
    
    public FeedbackType getFeedbackType() { return feedbackType; }
    public void setFeedbackType(FeedbackType feedbackType) { this.feedbackType = feedbackType; }
    
    public FeedbackSource getSource() { return source; }
    public void setSource(FeedbackSource source) { this.source = source; }
    
    public String getReviewerId() { return reviewerId; }
    public void setReviewerId(String reviewerId) { this.reviewerId = reviewerId; }
    
    public String getComments() { return comments; }
    public void setComments(String comments) { this.comments = comments; }
    
    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }

} 