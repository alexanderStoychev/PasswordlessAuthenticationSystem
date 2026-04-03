package com.passwordless.auth.controller;

import com.passwordless.auth.model.LoginEventFeedback;
import com.passwordless.auth.service.FeedbackLearningService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * REST controller for managing machine learning feedback on security evaluations.
 * Provides endpoints for recording feedback, viewing learning insights, and managing
 * the adaptive security system's rule weights.
 * 
 * This controller enables:
 * - Security analysts to provide feedback on login evaluations
 * - Users to report false positives
 * - Administrators to monitor and tune the learning system
 * - System integration for automated feedback collection
 */
@RestController
@RequestMapping("/api/feedback")
@CrossOrigin(origins = "*")
public class FeedbackController {

    @Autowired
    private FeedbackLearningService feedbackLearningService;

    /**
     * Records comprehensive feedback for a login event evaluation.
     * Supports flexible feedback recording with full context and source attribution.
     * 
     * @param request Complete feedback details including type, source, and comments
     * @return Response indicating success, warning, or error status
     */
    @PostMapping("/record")
    public ResponseEntity<Map<String, Object>> recordFeedback(@RequestBody FeedbackRequest request) {
        try {
            LoginEventFeedback feedback = feedbackLearningService.recordFeedback(
                    request.getLoginEventId(),
                    request.getFeedbackType(),
                    request.getSource(),
                    request.getReviewerId(),
                    request.getComments()
            );

            Map<String, Object> response = new HashMap<>();
            if (feedback != null) {
                response.put("status", "success");
                response.put("message", "Feedback recorded successfully");
                response.put("feedbackId", feedback.getId());
                return ResponseEntity.ok(response);
            } else {
                response.put("status", "warning");
                response.put("message", "Feedback already exists for this login event");
                return ResponseEntity.ok(response);
            }

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "error",
                    "message", e.getMessage()
            ));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "status", "error",
                    "message", "Failed to record feedback: " + e.getMessage()
            ));
        }
    }

    /**
     * Quick endpoint for marking a security evaluation as correct (true positive).
     * Used when the system correctly identified a legitimate security threat.
     * 
     * @param loginEventId ID of the login event being evaluated
     * @param reviewerId Optional identifier of the reviewer providing feedback
     * @param comments Optional additional context about the evaluation
     * @return Response indicating feedback recording status
     */
    @PostMapping("/true-positive/{loginEventId}")
    public ResponseEntity<Map<String, Object>> markTruePositive(
            @PathVariable UUID loginEventId,
            @RequestParam(required = false) String reviewerId,
            @RequestParam(required = false) String comments) {

        return recordQuickFeedback(loginEventId, LoginEventFeedback.FeedbackType.TRUE_POSITIVE,
                reviewerId, comments);
    }

    /**
     * Quick endpoint for marking a security evaluation as incorrect (false positive).
     * Used when the system incorrectly flagged a legitimate user activity.
     * 
     * @param loginEventId ID of the login event being evaluated
     * @param reviewerId Optional identifier of the reviewer providing feedback
     * @param comments Optional additional context about the false positive
     * @return Response indicating feedback recording status
     */
    @PostMapping("/true-negative/{loginEventId}")
    public ResponseEntity<Map<String, Object>> markTrueNegative(
            @PathVariable UUID loginEventId,
            @RequestParam(required = false) String reviewerId,
            @RequestParam(required = false) String comments) {

        return recordQuickFeedback(loginEventId, LoginEventFeedback.FeedbackType.TRUE_NEGATIVE,
                reviewerId, comments);
    }

    /**
     * Helper method for recording quick feedback with consistent error handling.
     * Centralizes the feedback recording logic for the convenience endpoints.
     * 
     * @param loginEventId ID of the login event
     * @param feedbackType Type of feedback being provided
     * @param reviewerId Optional reviewer identifier
     * @param comments Optional additional comments
     * @return Standardized response with status and details
     */
    private ResponseEntity<Map<String, Object>> recordQuickFeedback(UUID loginEventId,
                                                                    LoginEventFeedback.FeedbackType feedbackType,
                                                                    String reviewerId,
                                                                    String comments) {
        try {
            LoginEventFeedback feedback = feedbackLearningService.recordFeedback(
                    loginEventId,
                    feedbackType,
                    LoginEventFeedback.FeedbackSource.ADMIN_REVIEW,
                    reviewerId != null ? reviewerId : "system",
                    comments

            );

            Map<String, Object> response = new HashMap<>();
            if (feedback != null) {
                response.put("status", "success");
                response.put("message", "Feedback recorded: " + feedbackType);
                response.put("feedbackId", feedback.getId());
                return ResponseEntity.ok(response);
            } else {
                response.put("status", "warning");
                response.put("message", "Feedback already exists for this login event");
                return ResponseEntity.ok(response);
            }

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "error",
                    "message", e.getMessage()
            ));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "status", "error",
                    "message", "Failed to record feedback: " + e.getMessage()
            ));
        }
    }

    /**
     * Provides comprehensive insights into the machine learning system's performance.
     * Returns metrics on feedback rates, rule effectiveness, and learning progress.
     * Used by administrators to monitor and tune the adaptive security system.
     * 
     * @return Learning insights including accuracy metrics and rule performance
     */
    @GetMapping("/insights")
    public ResponseEntity<Map<String, Object>> getLearningInsights() {
        try {
            Map<String, Object> insights = feedbackLearningService.generateLearningInsights();
            return ResponseEntity.ok(insights);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "status", "error",
                    "message", "Failed to generate insights: " + e.getMessage()
            ));
        }
    }

    /**
     * Returns current security rule weights for monitoring and debugging.
     * Shows how the machine learning system has adjusted rule importance
     * based on historical feedback and effectiveness.
     * 
     * @return Current weights for all security detection rules
     */
    @GetMapping("/rule-weights")
    public ResponseEntity<Map<String, Object>> getRuleWeights() {
        try {
            Map<String, Double> weights = feedbackLearningService.getCurrentRuleWeights();
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "ruleWeights", weights
            ));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "status", "error",
                    "message", "Failed to get rule weights: " + e.getMessage()
            ));
        }
    }

    /**
     * Resets all machine learning rule weights back to default values.
     * Administrative endpoint used when the learning system needs to be restarted
     * or when weights have drifted too far from optimal values.
     * 
     * @return Response confirming successful reset or error details
     */
    @PostMapping("/reset-weights")
    public ResponseEntity<Map<String, Object>> resetRuleWeights() {
        try {
            feedbackLearningService.resetRuleWeights();
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "Rule weights reset to defaults"
            ));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "status", "error",
                    "message", "Failed to reset weights: " + e.getMessage()
            ));
        }
    }

    /**
     * Data transfer object for comprehensive feedback recording requests.
     * Provides flexibility for different feedback sources and detailed context.
     */
    public static class FeedbackRequest {
        /** ID of the login event being evaluated */
        private UUID loginEventId;
        
        /** Type of feedback indicating evaluation correctness */
        private LoginEventFeedback.FeedbackType feedbackType;
        
        /** Source of the feedback for credibility weighting */
        private LoginEventFeedback.FeedbackSource source;
        
        /** Identifier of the person providing feedback */
        private String reviewerId;
        
        /** Additional context or comments about the feedback */
        private String comments;

        public UUID getLoginEventId() { return loginEventId; }
        public void setLoginEventId(UUID loginEventId) { this.loginEventId = loginEventId; }

        public LoginEventFeedback.FeedbackType getFeedbackType() { return feedbackType; }
        public void setFeedbackType(LoginEventFeedback.FeedbackType feedbackType) { this.feedbackType = feedbackType; }

        public LoginEventFeedback.FeedbackSource getSource() { return source; }
        public void setSource(LoginEventFeedback.FeedbackSource source) { this.source = source; }

        public String getReviewerId() { return reviewerId; }
        public void setReviewerId(String reviewerId) { this.reviewerId = reviewerId; }

        public String getComments() { return comments; }
        public void setComments(String comments) { this.comments = comments; }

    }
}
