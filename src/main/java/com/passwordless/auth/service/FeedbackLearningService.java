package com.passwordless.auth.service;

import com.passwordless.auth.model.LoginEvent;
import com.passwordless.auth.model.LoginEventFeedback;
import com.passwordless.auth.model.User;
import com.passwordless.auth.repository.LoginEventFeedbackRepository;
import com.passwordless.auth.repository.LoginEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service implementing machine learning-based feedback system for security rule adaptation.
 * Dynamically adjusts security rule weights based on human feedback and incident data
 * to reduce false positives while maintaining threat detection effectiveness.
 * 
 * This service provides adaptive security by:
 * - Learning from security analyst feedback
 * - Adjusting rule weights based on effectiveness
 * - Personalizing security thresholds per user
 * - Generating insights on detection accuracy
 */
@Service
public class FeedbackLearningService {

    private static final Logger logger = LoggerFactory.getLogger(FeedbackLearningService.class);

    @Autowired
    private LoginEventFeedbackRepository feedbackRepository;

    @Autowired
    private LoginEventRepository loginEventRepository;

    /** Dynamic weights for security rules, adjusted based on feedback */
    private final Map<String, Double> ruleWeights = new HashMap<>();
    
    /** User-specific weight multipliers for personalized security */
    private final Map<String, Double> userSpecificWeights = new HashMap<>();

    /**
     * Constructor initializes the service with default security rule weights.
     */
    public FeedbackLearningService() {
        initializeDefaultWeights();
    }

    /**
     * Sets initial weights for security rules based on domain expertise.
     * These weights represent the baseline threat levels for different indicators.
     */
    private void initializeDefaultWeights() {
        ruleWeights.put("new_ip", 0.9);          // New IP addresses - high risk
        ruleWeights.put("new_device", 0.9);      // New devices - high risk  
        ruleWeights.put("unusual_time", 0.7);    // Off-hours access - medium risk
        ruleWeights.put("rapid_logins", 1.4);    // Bot-like activity - very high risk
        ruleWeights.put("recent_failures", 1.2); // Brute force indicators - very high risk
    }

    /**
     * Records feedback on a security evaluation and updates machine learning weights.
     * This is the core method that enables the system to learn and adapt.
     * 
     * @param loginEventId ID of the login event being evaluated
     * @param feedbackType Whether the original evaluation was correct
     * @param source Who provided this feedback (affects credibility)
     * @param reviewerId Identifier of the human reviewer
     * @param comments Additional context about the feedback
     * @return Saved feedback record, or null if feedback already exists
     */
    public LoginEventFeedback recordFeedback(UUID loginEventId,
                                             LoginEventFeedback.FeedbackType feedbackType,
                                             LoginEventFeedback.FeedbackSource source,
                                             String reviewerId,
                                             String comments
                                            ) {

        Optional<LoginEvent> loginEventOpt = loginEventRepository.findById(loginEventId);
        if (loginEventOpt.isEmpty()) {
            throw new IllegalArgumentException("Login event not found: " + loginEventId);
        }

        LoginEvent loginEvent = loginEventOpt.get();

        // Prevent duplicate feedback on the same event
        if (feedbackRepository.existsByLoginEvent(loginEvent)) {
            logger.warn("Feedback already exists for login event: {}", loginEventId);
            return null;
        }

        // Create and save feedback record
        LoginEventFeedback feedback = new LoginEventFeedback(loginEvent, feedbackType, source, reviewerId);
        feedback.setComments(comments);

        LoginEventFeedback savedFeedback = feedbackRepository.save(feedback);

        // Apply machine learning weight updates
        updateRuleWeights(loginEvent, feedbackType);

        logger.info("Feedback recorded for login event {}: {} by {} (confidence: {})",
                loginEventId, feedbackType, reviewerId);

        return savedFeedback;
    }

    /**
     * Updates security rule weights based on feedback effectiveness.
     * Increases weights for rules that correctly identified threats,
     * decreases weights for rules that caused false positives.
     * 
     * @param loginEvent The login event that was evaluated
     * @param feedbackType Whether the evaluation was correct
     */
    private void updateRuleWeights(LoginEvent loginEvent, LoginEventFeedback.FeedbackType feedbackType) {
        try {
            List<String> triggeredRules = parseTriggeredRules(loginEvent.getTriggeredRules());

            // Update weight for each rule that was triggered
            for (String rule : triggeredRules) {
                double currentWeight = ruleWeights.getOrDefault(rule, 0.5);
                double adjustment = calculateWeightAdjustment(feedbackType);

                // Keep weights within reasonable bounds (0.1 to 1.0)
                double newWeight = Math.max(0.1, Math.min(1.0, currentWeight + adjustment));
                ruleWeights.put(rule, newWeight);

                logger.debug("Updated weight for rule '{}': {} -> {} (adjustment: {})",
                        rule, currentWeight, newWeight, adjustment);
            }

            // Also update user-specific patterns
            updateUserSpecificWeights(loginEvent.getUser(), feedbackType);

        } catch (Exception e) {
            logger.error("Error updating rule weights for login event {}: {}", loginEvent.getId(), e.getMessage());
        }
    }

    /**
     * Calculates weight adjustment based on feedback type.
     * Positive adjustments strengthen rules that work well,
     * negative adjustments weaken rules that cause false positives.
     * 
     * @param feedbackType Type of feedback received
     * @return Weight adjustment amount
     */
    private double calculateWeightAdjustment(LoginEventFeedback.FeedbackType feedbackType) {
        return switch (feedbackType) {
            case TRUE_POSITIVE -> 0.05;   // Rule correctly flagged threat - strengthen it
            case TRUE_NEGATIVE -> -0.025;  // Rule caused false positive - weaken it
        };
    }

    /**
     * Updates user-specific weight multipliers for personalized security.
     * Some users may have legitimate patterns that look suspicious to general rules.
     * 
     * @param user User account to update personalization for
     * @param feedbackType Type of feedback received
     */
    private void updateUserSpecificWeights(User user, LoginEventFeedback.FeedbackType feedbackType) {
        String userKey = "user_" + user.getId();
        double currentWeight = userSpecificWeights.getOrDefault(userKey, 1.0);

        double adjustment = switch (feedbackType) {
            case TRUE_POSITIVE -> 0.015;  // Increase sensitivity for this user
            case TRUE_NEGATIVE -> -0.015; // Decrease sensitivity for this user
        };

        // Keep user multipliers between 0.5 and 1.5
        double newWeight = Math.max(0.5, Math.min(1.5, currentWeight + adjustment));
        userSpecificWeights.put(userKey, newWeight);

        logger.debug("Updated user-specific weight for user {}: {} -> {}",
                user.getUsername(), currentWeight, newWeight);
    }

    /**
     * Applies machine learning adjustments to get final security evaluation.
     * Combines rule-based evaluation with learned patterns and user personalization.
     * 
     * @param triggeredRules List of security rules that were triggered
     * @param user User account for personalized adjustments
     * @param originalResult Original rule-based evaluation
     * @return Final security evaluation with ML adjustments
     */
    public LoginEvent.EvaluationResult getAdjustedEvaluationResult(List<String> triggeredRules,
                                                                   User user,
                                                                   LoginEvent.EvaluationResult originalResult) {
        if (triggeredRules.isEmpty()) {
            return LoginEvent.EvaluationResult.ALLOW;
        }

        // Calculate weighted risk score
        double riskScore = 0.0;
        for (String rule : triggeredRules) {
            double weight = ruleWeights.getOrDefault(rule, 0.5);
            riskScore += weight;
        }

        // Apply user-specific personalization
        String userKey = "user_" + user.getId();
        double userMultiplier = userSpecificWeights.getOrDefault(userKey, 1.0);
        riskScore *= userMultiplier;

        // Convert risk score to evaluation result
        if (riskScore >= 1.5) {
            return LoginEvent.EvaluationResult.DENY;
        } else if (riskScore >= 0.5) {
            return LoginEvent.EvaluationResult.RED_FLAG;
        } else {
            return LoginEvent.EvaluationResult.ALLOW;
        }
    }

    /**
     * Generates comprehensive insights about the learning system performance.
     * Used for monitoring machine learning effectiveness and detection accuracy.
     * 
     * @return Map containing various learning metrics and insights
     */
    public Map<String, Object> generateLearningInsights() {
        Map<String, Object> insights = new HashMap<>();

        LocalDateTime since = LocalDateTime.now().minusDays(30);
        List<LoginEventFeedback> recentFeedback = feedbackRepository.findRecentFeedback(since);

        // Calculate overall feedback statistics
        long totalFeedback = recentFeedback.size();
        long positives = recentFeedback.stream()
                .mapToLong(f -> f.getFeedbackType() == LoginEventFeedback.FeedbackType.TRUE_POSITIVE ? 1 : 0)
                .sum();
        long negatives = recentFeedback.stream()
                .mapToLong(f -> f.getFeedbackType() == LoginEventFeedback.FeedbackType.TRUE_NEGATIVE ? 1 : 0)
                .sum();

        insights.put("totalFeedback", totalFeedback);
        insights.put("positiveRate", totalFeedback > 0 ? (double) positives / totalFeedback : 0.0);
        insights.put("negativeRate", totalFeedback > 0 ? (double) negatives / totalFeedback : 0.0);
        insights.put("currentRuleWeights", new HashMap<>(ruleWeights));
        insights.put("learningPeriod", "Last 30 days");

        // Generate per-rule effectiveness insights
        Map<String, Object> ruleInsights = new HashMap<>();
        for (String rule : ruleWeights.keySet()) {
            List<Object[]> ruleStats = feedbackRepository.getFeedbackStatsForRule(rule, since);
            Map<String, Long> ruleFeedback = new HashMap<>();
            for (Object[] stat : ruleStats) {
                ruleFeedback.put(stat[0].toString(), (Long) stat[1]);
            }
            ruleInsights.put(rule, Map.of(
                    "weight", ruleWeights.get(rule),
                    "feedback", ruleFeedback
            ));
        }
        insights.put("ruleInsights", ruleInsights);

        return insights;
    }

    /**
     * Parses JSON string of triggered rules back into a list.
     * Handles various formats and edge cases gracefully.
     * 
     * @param triggeredRulesJson JSON string representation of rules
     * @return List of rule names that were triggered
     */
    private List<String> parseTriggeredRules(String triggeredRulesJson) {
        try {
            if (triggeredRulesJson == null || triggeredRulesJson.trim().isEmpty()) {
                return new ArrayList<>();
            }

            // Clean up JSON formatting
            String cleaned = triggeredRulesJson.replaceAll("[\\[\\]\"]", "");
            if (cleaned.trim().isEmpty()) {
                return new ArrayList<>();
            }

            // Split and clean individual rule names
            return Arrays.stream(cleaned.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .collect(Collectors.toList());

        } catch (Exception e) {
            logger.error("Error parsing triggered rules: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Returns current rule weights for monitoring and debugging.
     * 
     * @return Copy of current rule weights map
     */
    public Map<String, Double> getCurrentRuleWeights() {
        return new HashMap<>(ruleWeights);
    }

    /**
     * Resets all learned weights back to default values.
     * Used for testing or when learning has gone off track.
     */
    public void resetRuleWeights() {
        ruleWeights.clear();
        userSpecificWeights.clear();
        initializeDefaultWeights();
        logger.info("Rule weights reset to defaults");
    }

    /**
     * Alias for resetRuleWeights() for backwards compatibility.
     */
    public void resetToDefaultWeights() {
        resetRuleWeights();
    }
}
