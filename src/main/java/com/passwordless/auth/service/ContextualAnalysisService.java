package com.passwordless.auth.service;

import com.passwordless.auth.model.LoginEvent;
import com.passwordless.auth.model.User;
import com.passwordless.auth.repository.LoginEventRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class ContextualAnalysisService {

    private static final Logger logger = LoggerFactory.getLogger(ContextualAnalysisService.class);

    @Autowired
    private LoginEventRepository loginEventRepository;

    @Autowired
    private FeedbackLearningService feedbackLearningService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    public static class LoginAnalysisResult {
        private LoginEvent.EvaluationResult evaluationResult;
        private List<String> triggeredRules;

        public LoginAnalysisResult(LoginEvent.EvaluationResult evaluationResult, List<String> triggeredRules) {
            this.evaluationResult = evaluationResult;
            this.triggeredRules = triggeredRules;
        }

        public LoginEvent.EvaluationResult getEvaluationResult() { return evaluationResult; }
        public List<String> getTriggeredRules() { return triggeredRules; }
    }

    public LoginAnalysisResult analyzeLoginAttempt(User user, String ipAddress, String userAgent, LocalDateTime timestamp) {
        List<String> triggeredRules = new ArrayList<>();

        if (exceedsTrustedIpLimit(user, ipAddress)) {
            triggeredRules.add("new_ip");
        }

        if (isUnusualTime(timestamp)) {
            triggeredRules.add("late_night");
        }

        if (exceedsTrustedDeviceLimit(user, userAgent)) {
            triggeredRules.add("new_device");
        }

        if (hasRapidSuccessiveLogins(user, timestamp)) {
            triggeredRules.add("rapid_logins");
        }

        if (hasRecentFailedAttempts(user, timestamp)) {
            triggeredRules.add("recent_failures");
        }

        LoginEvent.EvaluationResult result = determineEvaluationResult(triggeredRules, user);

        logger.info("Login analysis for user {}: {} - Triggered rules: {}",
                user.getUsername(), result, triggeredRules);

        return new LoginAnalysisResult(result, triggeredRules);
    }

    // TRIGGERS new_ip only if over 2 trusted IPs
    private boolean exceedsTrustedIpLimit(User user, String ipAddress) {
        LocalDateTime oneMonthAgo = LocalDateTime.now().minusMonths(1);
        List<LoginEvent> recentLogins = loginEventRepository.findRecentLoginsByUser(user, oneMonthAgo);

        Set<String> knownIps = new HashSet<>();
        for (LoginEvent event : recentLogins) {
            knownIps.add(event.getIpAddress());
        }

        return !knownIps.contains(ipAddress) && knownIps.size() >= 2;
    }

    // TRIGGERS new_device only if over 2 trusted user agents
    private boolean exceedsTrustedDeviceLimit(User user, String userAgent) {
        LocalDateTime oneMonthAgo = LocalDateTime.now().minusMonths(1);
        List<LoginEvent> recentLogins = loginEventRepository.findRecentLoginsByUser(user, oneMonthAgo);

        Set<String> knownAgents = new HashSet<>();
        for (LoginEvent event : recentLogins) {
            knownAgents.add(event.getUserAgent());
        }

        return !knownAgents.contains(userAgent) && knownAgents.size() >= 2;
    }

    private boolean isUnusualTime(LocalDateTime timestamp) {
        LocalTime time = timestamp.toLocalTime();
        return time.isAfter(LocalTime.of(23, 0)) || time.isBefore(LocalTime.of(6, 0));
    }

    private boolean hasRapidSuccessiveLogins(User user, LocalDateTime timestamp) {
        LocalDateTime fiveMinutesAgo = timestamp.minusMinutes(5);
        List<LoginEvent> recentLogins = loginEventRepository.findRecentLoginsByUser(user, fiveMinutesAgo);
        return recentLogins.size() > 3;
    }

    private boolean hasRecentFailedAttempts(User user, LocalDateTime timestamp) {
        LocalDateTime oneHourAgo = timestamp.minusHours(1);
        List<LoginEvent> recentLogins = loginEventRepository.findRecentLoginsByUser(user, oneHourAgo);

        long failedAttempts = recentLogins.stream()
                .filter(event -> event.getEvaluationResult() == LoginEvent.EvaluationResult.DENY)
                .count();

        return failedAttempts >= 3;
    }

    private LoginEvent.EvaluationResult determineEvaluationResult(List<String> triggeredRules, User user) {
        if (triggeredRules.isEmpty()) {
            return LoginEvent.EvaluationResult.ALLOW;
        }

        LoginEvent.EvaluationResult originalResult = determineOriginalEvaluationResult(triggeredRules);
        return feedbackLearningService.getAdjustedEvaluationResult(triggeredRules, user, originalResult);
    }

    private LoginEvent.EvaluationResult determineOriginalEvaluationResult(List<String> triggeredRules) {
        if (triggeredRules.contains("recent_failures") || triggeredRules.contains("rapid_logins")) {
            return LoginEvent.EvaluationResult.DENY;
        }
        if (triggeredRules.contains("new_ip") || triggeredRules.contains("new_device")) {
            return LoginEvent.EvaluationResult.RED_FLAG;
        }
        if (triggeredRules.contains("unusual_time")) {
            return LoginEvent.EvaluationResult.RED_FLAG;
        }
        return LoginEvent.EvaluationResult.ALLOW;
    }

    public String convertTriggeredRulesToJson(List<String> triggeredRules) {
        try {
            return objectMapper.writeValueAsString(triggeredRules);
        } catch (JsonProcessingException e) {
            logger.error("Failed to convert triggered rules to JSON", e);
            return "[]";
        }
    }
}
