package com.passwordless.auth.service;

import com.passwordless.auth.model.LoginEvent;
import com.passwordless.auth.model.User;
import com.passwordless.auth.repository.LoginEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive test suite for the ContextualAnalysisService.
 * Tests security analysis algorithms and threat detection logic.
 */
class ContextualAnalysisServiceTest {

    @Mock
    private LoginEventRepository loginEventRepository;

    @Mock
    private FeedbackLearningService feedbackLearningService;

    @InjectMocks
    private ContextualAnalysisService contextualAnalysisService;

    private User testUser;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        // Setup test user
        testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("testuser");
    }

    @Test
    void testNormalLoginScenario() {
        // Setup normal login history
        List<LoginEvent> recentLogins = Arrays.asList(
            createLoginEvent("192.168.1.100", "US", LocalDateTime.now().minusHours(1)),
            createLoginEvent("192.168.1.101", "US", LocalDateTime.now().minusHours(3))
        );

        when(loginEventRepository.findRecentLoginsByUser(eq(testUser), any(LocalDateTime.class)))
            .thenReturn(recentLogins);
        when(feedbackLearningService.getAdjustedEvaluationResult(anyList(), eq(testUser), any()))
            .thenReturn(LoginEvent.EvaluationResult.ALLOW);

        // Execute analysis
        Object result = contextualAnalysisService.analyzeLoginAttempt(
            testUser, 
            "192.168.1.100", 
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", 
            LocalDateTime.now()
        );

        // Verify normal login is allowed
        assertEquals(LoginEvent.EvaluationResult.ALLOW, invokeMethod(result, "getEvaluationResult"));
        // The service calls the repository multiple times for different checks
        verify(loginEventRepository, atLeast(1)).findRecentLoginsByUser(eq(testUser), any(LocalDateTime.class));
    }

    @Test
    void testNewIpAddressDetection() {
        // Setup login history with different IPs (more than 2 to trigger new_ip rule)
        List<LoginEvent> recentLogins = Arrays.asList(
            createLoginEvent("10.0.0.1", "US", LocalDateTime.now().minusHours(1)),
            createLoginEvent("10.0.0.2", "US", LocalDateTime.now().minusHours(3)),
            createLoginEvent("10.0.0.3", "US", LocalDateTime.now().minusHours(5))
        );

        when(loginEventRepository.findRecentLoginsByUser(eq(testUser), any(LocalDateTime.class)))
            .thenReturn(recentLogins);
        when(feedbackLearningService.getAdjustedEvaluationResult(anyList(), eq(testUser), any()))
            .thenReturn(LoginEvent.EvaluationResult.RED_FLAG);

        // Execute analysis with new IP
        Object result = contextualAnalysisService.analyzeLoginAttempt(
            testUser, 
            "203.0.113.1", // New IP not in history
            "Mozilla/5.0", 
            LocalDateTime.now()
        );

        // Should trigger new IP rule
        assertEquals(LoginEvent.EvaluationResult.RED_FLAG, invokeMethod(result, "getEvaluationResult"));
        assertTrue(((List<String>)invokeMethod(result, "getTriggeredRules")).contains("new_ip"));
    }

    @Test
    void testUnusualTimingDetection() {
        // Setup login history during normal hours
        List<LoginEvent> recentLogins = Arrays.asList(
            createLoginEvent("192.168.1.100", "US", LocalDateTime.now().withHour(9).withMinute(0))
        );

        when(loginEventRepository.findRecentLoginsByUser(eq(testUser), any(LocalDateTime.class)))
            .thenReturn(recentLogins);
        when(feedbackLearningService.getAdjustedEvaluationResult(anyList(), eq(testUser), any()))
            .thenReturn(LoginEvent.EvaluationResult.RED_FLAG);

        // Execute analysis at unusual time (3 AM)
        LocalDateTime unusualTime = LocalDateTime.now().withHour(3).withMinute(0);
        Object result = contextualAnalysisService.analyzeLoginAttempt(
            testUser, 
            "192.168.1.100", 
            "Mozilla/5.0", 
            unusualTime
        );

        // Should trigger late night rule
        assertNotNull(result);
        assertTrue(((List<String>)invokeMethod(result, "getTriggeredRules")).contains("late_night"));
    }

    @Test
    void testFrequencyAnalysisDetection() {
        // Setup multiple recent logins (potential brute force)
        List<LoginEvent> recentLogins = Arrays.asList(
            createLoginEvent("192.168.1.100", "US", LocalDateTime.now().minusMinutes(1)),
            createLoginEvent("192.168.1.100", "US", LocalDateTime.now().minusMinutes(2)),
            createLoginEvent("192.168.1.100", "US", LocalDateTime.now().minusMinutes(3)),
            createLoginEvent("192.168.1.100", "US", LocalDateTime.now().minusMinutes(4))
        );

        when(loginEventRepository.findRecentLoginsByUser(eq(testUser), any(LocalDateTime.class)))
            .thenReturn(recentLogins);
        when(feedbackLearningService.getAdjustedEvaluationResult(anyList(), eq(testUser), any()))
            .thenReturn(LoginEvent.EvaluationResult.DENY);

        // Execute analysis
        Object result = contextualAnalysisService.analyzeLoginAttempt(
            testUser, 
            "192.168.1.100", 
            "Mozilla/5.0", 
            LocalDateTime.now()
        );

        // Should detect high frequency as suspicious
        assertEquals(LoginEvent.EvaluationResult.DENY, invokeMethod(result, "getEvaluationResult"));
        assertTrue(((List<String>)invokeMethod(result, "getTriggeredRules")).contains("rapid_logins"));
    }

    @Test
    void testNewDeviceDetection() {
        // Setup login history with different user agents (more than 2 to trigger new_device rule)
        List<LoginEvent> recentLogins = Arrays.asList(
            createLoginEventWithUserAgent("192.168.1.100", "US", 
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", LocalDateTime.now().minusHours(1)),
            createLoginEventWithUserAgent("192.168.1.100", "US", 
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", LocalDateTime.now().minusHours(2)),
            createLoginEventWithUserAgent("192.168.1.100", "US", 
                "Mozilla/5.0 (X11; Linux x86_64)", LocalDateTime.now().minusHours(3))
        );

        when(loginEventRepository.findRecentLoginsByUser(eq(testUser), any(LocalDateTime.class)))
            .thenReturn(recentLogins);
        when(feedbackLearningService.getAdjustedEvaluationResult(anyList(), eq(testUser), any()))
            .thenReturn(LoginEvent.EvaluationResult.RED_FLAG);

        // Execute analysis with new device
        Object result = contextualAnalysisService.analyzeLoginAttempt(
            testUser, 
            "192.168.1.100", 
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)", // New user agent
            LocalDateTime.now()
        );

        // Should trigger new device rule
        assertEquals(LoginEvent.EvaluationResult.RED_FLAG, invokeMethod(result, "getEvaluationResult"));
        assertTrue(((List<String>)invokeMethod(result, "getTriggeredRules")).contains("new_device"));
    }

    @Test
    void testNoHistoryScenario() {
        // Setup empty login history (new user)
        when(loginEventRepository.findRecentLoginsByUser(eq(testUser), any(LocalDateTime.class)))
            .thenReturn(Collections.emptyList());

        // Execute analysis
        Object result = contextualAnalysisService.analyzeLoginAttempt(
            testUser, 
            "192.168.1.100", 
            "Mozilla/5.0", 
            LocalDateTime.now()
        );

        // Debug output to check result object
        System.out.println("Result object: " + result);
        Object evaluationResult = invokeMethod(result, "getEvaluationResult");
        System.out.println("Evaluation result: " + evaluationResult);

        // Should handle new user scenario gracefully (no rules triggered)
        assertEquals(LoginEvent.EvaluationResult.ALLOW, evaluationResult);
        assertTrue(((List<String>)invokeMethod(result, "getTriggeredRules")).isEmpty());
    }

    @Test
    void testRecentFailuresDetection() {
        // Setup recent failed login attempts
        List<LoginEvent> recentLogins = Arrays.asList(
            createFailedLoginEvent("192.168.1.100", "US", LocalDateTime.now().minusMinutes(10)),
            createFailedLoginEvent("192.168.1.100", "US", LocalDateTime.now().minusMinutes(20)),
            createFailedLoginEvent("192.168.1.100", "US", LocalDateTime.now().minusMinutes(30))
        );

        when(loginEventRepository.findRecentLoginsByUser(eq(testUser), any(LocalDateTime.class)))
            .thenReturn(recentLogins);
        when(feedbackLearningService.getAdjustedEvaluationResult(anyList(), eq(testUser), any()))
            .thenReturn(LoginEvent.EvaluationResult.DENY);

        // Execute analysis
        Object result = contextualAnalysisService.analyzeLoginAttempt(
            testUser, 
            "192.168.1.100", 
            "Mozilla/5.0", 
            LocalDateTime.now()
        );

        // Should trigger recent failures rule
        assertEquals(LoginEvent.EvaluationResult.DENY, invokeMethod(result, "getEvaluationResult"));
        assertTrue(((List<String>)invokeMethod(result, "getTriggeredRules")).contains("recent_failures"));
    }

    @Test
    void testTriggeredRulesJsonConversion() {
        // Test JSON conversion of triggered rules
        List<String> rules = Arrays.asList("new_ip", "unusual_time", "new_device");
        
        String json = contextualAnalysisService.convertTriggeredRulesToJson(rules);
        
        assertNotNull(json);
        assertTrue(json.contains("new_ip"));
        assertTrue(json.contains("unusual_time"));
        assertTrue(json.contains("new_device"));
    }

    @Test
    void testEmptyTriggeredRulesJsonConversion() {
        // Test JSON conversion of empty rules list
        List<String> rules = Collections.emptyList();
        
        String json = contextualAnalysisService.convertTriggeredRulesToJson(rules);
        
        assertNotNull(json);
        assertEquals("[]", json);
    }

    // Helper methods
    private LoginEvent createLoginEvent(String ipAddress, String country, LocalDateTime timestamp) {
        LoginEvent event = new LoginEvent();
        event.setId(UUID.randomUUID());
        event.setUser(testUser);
        event.setIpAddress(ipAddress);
        event.setCountry(country);
        event.setTimestamp(timestamp);
        event.setUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        event.setEvaluationResult(LoginEvent.EvaluationResult.ALLOW);
        return event;
    }

    private LoginEvent createLoginEventWithUserAgent(String ipAddress, String country, String userAgent, LocalDateTime timestamp) {
        LoginEvent event = createLoginEvent(ipAddress, country, timestamp);
        event.setUserAgent(userAgent);
        return event;
    }

    private LoginEvent createFailedLoginEvent(String ipAddress, String country, LocalDateTime timestamp) {
        LoginEvent event = createLoginEvent(ipAddress, country, timestamp);
        event.setEvaluationResult(LoginEvent.EvaluationResult.DENY);
        return event;
    }

    // Helper method to invoke methods via reflection to avoid direct inner class reference
    private Object invokeMethod(Object obj, String methodName) {
        try {
            java.lang.reflect.Method method = obj.getClass().getMethod(methodName);
            return method.invoke(obj);
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke method " + methodName, e);
        }
    }
} 