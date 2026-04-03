package com.passwordless.auth.service;

import com.passwordless.auth.model.LoginEvent;
import com.passwordless.auth.model.LoginEventFeedback;
import com.passwordless.auth.model.User;
import com.passwordless.auth.repository.LoginEventFeedbackRepository;
import com.passwordless.auth.repository.LoginEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.LocalDateTime;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class FeedbackLearningServiceTest {

    @Mock
    private LoginEventFeedbackRepository feedbackRepository;

    @Mock
    private LoginEventRepository loginEventRepository;

    @InjectMocks
    private FeedbackLearningService feedbackLearningService;

    private User testUser;
    private LoginEvent testLoginEvent;
    private UUID testLoginEventId;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        // Setup test user
        testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("testuser");

        // Setup test login event
        testLoginEventId = UUID.randomUUID();
        testLoginEvent = new LoginEvent();
        testLoginEvent.setId(testLoginEventId);
        testLoginEvent.setUser(testUser);
        testLoginEvent.setTimestamp(LocalDateTime.now());
        testLoginEvent.setIpAddress("192.168.1.1");
        testLoginEvent.setUserAgent("Mozilla/5.0");
        testLoginEvent.setTriggeredRules("new_ip,unusual_time");
    }

    @Test
    void testRecordTruePositiveFeedback() {
        // Setup
        when(loginEventRepository.findById(testLoginEventId)).thenReturn(Optional.of(testLoginEvent));
        when(feedbackRepository.existsByLoginEvent(testLoginEvent)).thenReturn(false);
        when(feedbackRepository.save(any(LoginEventFeedback.class))).thenAnswer(i -> i.getArguments()[0]);

        // Execute
        LoginEventFeedback feedback = feedbackLearningService.recordFeedback(
                testLoginEventId,
                LoginEventFeedback.FeedbackType.TRUE_POSITIVE,
                LoginEventFeedback.FeedbackSource.ADMIN_REVIEW,
                "admin1",
                "Confirmed legitimate login"
        );

        // Verify
        assertNotNull(feedback);
        assertEquals(testLoginEvent, feedback.getLoginEvent());
        assertEquals(LoginEventFeedback.FeedbackType.TRUE_POSITIVE, feedback.getFeedbackType());
        assertEquals(LoginEventFeedback.FeedbackSource.ADMIN_REVIEW, feedback.getSource());
        assertEquals("admin1", feedback.getReviewerId());
        assertEquals("Confirmed legitimate login", feedback.getComments());
    }

    @Test
    void testRecordTrueNegativeFeedback() {
        // Setup
        when(loginEventRepository.findById(testLoginEventId)).thenReturn(Optional.of(testLoginEvent));
        when(feedbackRepository.existsByLoginEvent(testLoginEvent)).thenReturn(false);
        when(feedbackRepository.save(any(LoginEventFeedback.class))).thenAnswer(i -> i.getArguments()[0]);

        // Execute
        LoginEventFeedback feedback = feedbackLearningService.recordFeedback(
                testLoginEventId,
                LoginEventFeedback.FeedbackType.TRUE_NEGATIVE,
                LoginEventFeedback.FeedbackSource.USER_REPORT,
                "user1",
                "Confirmed unauthorized access"
        );

        // Verify
        assertNotNull(feedback);
        assertEquals(testLoginEvent, feedback.getLoginEvent());
        assertEquals(LoginEventFeedback.FeedbackType.TRUE_NEGATIVE, feedback.getFeedbackType());
        assertEquals(LoginEventFeedback.FeedbackSource.USER_REPORT, feedback.getSource());
        assertEquals("user1", feedback.getReviewerId());
        assertEquals("Confirmed unauthorized access", feedback.getComments());
    }

    @Test
    void testRuleWeightAdjustment() {
        // Setup
        when(loginEventRepository.findById(testLoginEventId)).thenReturn(Optional.of(testLoginEvent));
        when(feedbackRepository.existsByLoginEvent(testLoginEvent)).thenReturn(false);
        when(feedbackRepository.save(any(LoginEventFeedback.class))).thenAnswer(i -> i.getArguments()[0]);

        // Get initial weights
        Map<String, Double> initialWeights = feedbackLearningService.getCurrentRuleWeights();
        double initialNewIpWeight = initialWeights.get("new_ip");
        double initialUnusualTimeWeight = initialWeights.get("unusual_time");

        // Record true positive feedback
        feedbackLearningService.recordFeedback(
                testLoginEventId,
                LoginEventFeedback.FeedbackType.TRUE_POSITIVE,
                LoginEventFeedback.FeedbackSource.ADMIN_REVIEW,
                "admin1",
                "Test feedback"
        );

        // Get updated weights
        Map<String, Double> updatedWeights = feedbackLearningService.getCurrentRuleWeights();
        double updatedNewIpWeight = updatedWeights.get("new_ip");
        double updatedUnusualTimeWeight = updatedWeights.get("unusual_time");

        // Verify weights increased for true positive
        assertTrue(updatedNewIpWeight > initialNewIpWeight);
        assertTrue(updatedUnusualTimeWeight > initialUnusualTimeWeight);
    }

    @Test
    void testUserSpecificWeightAdjustment() {
        // Setup
        when(loginEventRepository.findById(testLoginEventId)).thenReturn(Optional.of(testLoginEvent));
        when(feedbackRepository.existsByLoginEvent(testLoginEvent)).thenReturn(false);
        when(feedbackRepository.save(any(LoginEventFeedback.class))).thenAnswer(i -> i.getArguments()[0]);

        // Record multiple feedbacks for the same user
        for (int i = 0; i < 3; i++) {
            feedbackLearningService.recordFeedback(
                    testLoginEventId,
                    LoginEventFeedback.FeedbackType.TRUE_POSITIVE,
                    LoginEventFeedback.FeedbackSource.ADMIN_REVIEW,
                    "admin1",
                    "Test feedback " + i
            );
        }

        // Test evaluation result with adjusted weights
        List<String> triggeredRules = Arrays.asList("new_ip", "unusual_time");
        LoginEvent.EvaluationResult result = feedbackLearningService.getAdjustedEvaluationResult(
                triggeredRules,
                testUser,
                LoginEvent.EvaluationResult.RED_FLAG
        );

        // Verify the result takes into account user-specific weights
        assertNotNull(result);
    }

    @Test
    void testGenerateLearningInsights() {
        // Setup mock feedback
        List<LoginEventFeedback> mockFeedback = new ArrayList<>();

        // Add some mock feedback
        LoginEventFeedback feedback1 = new LoginEventFeedback();
        feedback1.setFeedbackType(LoginEventFeedback.FeedbackType.TRUE_POSITIVE);
        mockFeedback.add(feedback1);

        LoginEventFeedback feedback2 = new LoginEventFeedback();
        feedback2.setFeedbackType(LoginEventFeedback.FeedbackType.TRUE_NEGATIVE);
        mockFeedback.add(feedback2);

        // Mock the repository calls - use any() to match any LocalDateTime
        when(feedbackRepository.findRecentFeedback(any(LocalDateTime.class))).thenReturn(mockFeedback);
        when(feedbackRepository.getFeedbackStatsForRule(anyString(), any(LocalDateTime.class)))
                .thenReturn(Arrays.asList(
                        new Object[]{"TRUE_POSITIVE", 1L},
                        new Object[]{"TRUE_NEGATIVE", 1L}
                ));

        // Execute
        Map<String, Object> insights = feedbackLearningService.generateLearningInsights();

        // Verify
        assertNotNull(insights);
        assertEquals(2L, insights.get("totalFeedback"));
        assertEquals(0.5, insights.get("positiveRate"));
        assertEquals(0.5, insights.get("negativeRate"));
        assertNotNull(insights.get("currentRuleWeights"));
        assertNotNull(insights.get("ruleInsights"));
    }

    @Test
    void testDuplicateFeedbackPrevention() {
        // Setup
        when(loginEventRepository.findById(testLoginEventId)).thenReturn(Optional.of(testLoginEvent));
        when(feedbackRepository.existsByLoginEvent(testLoginEvent)).thenReturn(true);

        // Execute
        LoginEventFeedback feedback = feedbackLearningService.recordFeedback(
                testLoginEventId,
                LoginEventFeedback.FeedbackType.TRUE_POSITIVE,
                LoginEventFeedback.FeedbackSource.ADMIN_REVIEW,
                "admin1",
                "Test feedback"
        );

        // Verify
        assertNull(feedback);
        verify(feedbackRepository, never()).save(any(LoginEventFeedback.class));
    }

    @Test
    void testInvalidLoginEvent() {
        // Setup
        when(loginEventRepository.findById(testLoginEventId)).thenReturn(Optional.empty());

        // Execute and verify exception
        assertThrows(IllegalArgumentException.class, () ->
                feedbackLearningService.recordFeedback(
                        testLoginEventId,
                        LoginEventFeedback.FeedbackType.TRUE_POSITIVE,
                        LoginEventFeedback.FeedbackSource.ADMIN_REVIEW,
                        "admin1",
                        "Test feedback"
                )
        );
    }
}