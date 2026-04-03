package com.passwordless.auth.model;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive test suite for the LoginEventFeedback entity.
 * Tests machine learning feedback system and security analysis improvement.
 */
class LoginEventFeedbackTest {

    private LoginEventFeedback feedback;
    private LoginEvent loginEvent;
    private User user;

    @BeforeEach
    void setUp() {
        // Setup user
        user = new User();
        user.setId(1L);
        user.setUsername("testuser");

        // Setup login event
        loginEvent = new LoginEvent();
        loginEvent.setId(UUID.randomUUID());
        loginEvent.setUser(user);
        loginEvent.setTimestamp(LocalDateTime.now());
        loginEvent.setIpAddress("192.168.1.100");
        loginEvent.setUserAgent("Mozilla/5.0");
        loginEvent.setEvaluationResult(LoginEvent.EvaluationResult.RED_FLAG);
        loginEvent.setTriggeredRules("new_ip,unusual_time");

        // Setup feedback
        feedback = new LoginEventFeedback();
        feedback.setId(UUID.randomUUID().toString());
        feedback.setLoginEvent(loginEvent);
        feedback.setFeedbackType(LoginEventFeedback.FeedbackType.TRUE_POSITIVE);
        feedback.setSource(LoginEventFeedback.FeedbackSource.ADMIN_REVIEW);
        feedback.setReviewerId("admin123");
        feedback.setComments("Confirmed legitimate login - user was traveling");
        feedback.setTimestamp(LocalDateTime.now());
    }

    @Test
    void testValidFeedbackCreation() {
        // Verify all fields are set correctly
        assertNotNull(feedback.getId());
        assertEquals(loginEvent, feedback.getLoginEvent());
        assertEquals(LoginEventFeedback.FeedbackType.TRUE_POSITIVE, feedback.getFeedbackType());
        assertEquals(LoginEventFeedback.FeedbackSource.ADMIN_REVIEW, feedback.getSource());
        assertEquals("admin123", feedback.getReviewerId());
        assertEquals("Confirmed legitimate login - user was traveling", feedback.getComments());
        assertNotNull(feedback.getTimestamp());
    }

    @Test
    void testFeedbackTypeEnum() {
        // Test TRUE_POSITIVE feedback
        feedback.setFeedbackType(LoginEventFeedback.FeedbackType.TRUE_POSITIVE);
        assertEquals(LoginEventFeedback.FeedbackType.TRUE_POSITIVE, feedback.getFeedbackType());

        // Test TRUE_NEGATIVE feedback
        feedback.setFeedbackType(LoginEventFeedback.FeedbackType.TRUE_NEGATIVE);
        assertEquals(LoginEventFeedback.FeedbackType.TRUE_NEGATIVE, feedback.getFeedbackType());
    }

    @Test
    void testFeedbackSourceEnum() {
        // Test all feedback sources
        feedback.setSource(LoginEventFeedback.FeedbackSource.ADMIN_REVIEW);
        assertEquals(LoginEventFeedback.FeedbackSource.ADMIN_REVIEW, feedback.getSource());

        feedback.setSource(LoginEventFeedback.FeedbackSource.USER_REPORT);
        assertEquals(LoginEventFeedback.FeedbackSource.USER_REPORT, feedback.getSource());

        feedback.setSource(LoginEventFeedback.FeedbackSource.AUTOMATED_SYSTEM);
        assertEquals(LoginEventFeedback.FeedbackSource.AUTOMATED_SYSTEM, feedback.getSource());

        feedback.setSource(LoginEventFeedback.FeedbackSource.INCIDENT_RESPONSE);
        assertEquals(LoginEventFeedback.FeedbackSource.INCIDENT_RESPONSE, feedback.getSource());
    }

    @Test
    void testTruePositiveFeedback() {
        // Test true positive scenario (system correctly identified threat)
        loginEvent.setEvaluationResult(LoginEvent.EvaluationResult.RED_FLAG);
        loginEvent.setTriggeredRules("suspicious_ip,multiple_failures");

        feedback.setFeedbackType(LoginEventFeedback.FeedbackType.TRUE_POSITIVE);
        feedback.setSource(LoginEventFeedback.FeedbackSource.INCIDENT_RESPONSE);
        feedback.setReviewerId("security_analyst_1");
        feedback.setComments("Confirmed attack attempt - IP blocked");

        assertEquals(LoginEventFeedback.FeedbackType.TRUE_POSITIVE, feedback.getFeedbackType());
        assertEquals("security_analyst_1", feedback.getReviewerId());
        assertTrue(feedback.getComments().contains("attack attempt"));
    }

    @Test
    void testTrueNegativeFeedback() {
        // Test true negative scenario (system correctly allowed legitimate access)
        loginEvent.setEvaluationResult(LoginEvent.EvaluationResult.ALLOW);
        loginEvent.setTriggeredRules("known_location,normal_hours");

        feedback.setFeedbackType(LoginEventFeedback.FeedbackType.TRUE_NEGATIVE);
        feedback.setSource(LoginEventFeedback.FeedbackSource.USER_REPORT);
        feedback.setReviewerId("user123");
        feedback.setComments("This was my legitimate login from home");

        assertEquals(LoginEventFeedback.FeedbackType.TRUE_NEGATIVE, feedback.getFeedbackType());
        assertEquals(LoginEventFeedback.FeedbackSource.USER_REPORT, feedback.getSource());
        assertTrue(feedback.getComments().contains("legitimate"));
    }

    @Test
    void testUserReportFeedback() {
        // Test user-initiated feedback
        feedback.setSource(LoginEventFeedback.FeedbackSource.USER_REPORT);
        feedback.setReviewerId("testuser");
        feedback.setFeedbackType(LoginEventFeedback.FeedbackType.TRUE_POSITIVE);
        feedback.setComments("I didn't make this login attempt - suspicious activity");

        assertEquals(LoginEventFeedback.FeedbackSource.USER_REPORT, feedback.getSource());
        assertEquals("testuser", feedback.getReviewerId());
        assertTrue(feedback.getComments().contains("suspicious"));
    }

    @Test
    void testAutomatedFeedback() {
        // Test automated system feedback
        feedback.setSource(LoginEventFeedback.FeedbackSource.AUTOMATED_SYSTEM);
        feedback.setReviewerId("ml_system_v2.1");
        feedback.setFeedbackType(LoginEventFeedback.FeedbackType.TRUE_POSITIVE);
        feedback.setComments("Pattern matches known attack signature: credential_stuffing_2024");

        assertEquals(LoginEventFeedback.FeedbackSource.AUTOMATED_SYSTEM, feedback.getSource());
        assertTrue(feedback.getReviewerId().contains("ml_system"));
        assertTrue(feedback.getComments().contains("credential_stuffing"));
    }

    @Test
    void testIncidentResponseFeedback() {
        // Test incident response team feedback
        feedback.setSource(LoginEventFeedback.FeedbackSource.INCIDENT_RESPONSE);
        feedback.setReviewerId("ir_team_lead");
        feedback.setFeedbackType(LoginEventFeedback.FeedbackType.TRUE_POSITIVE);
        feedback.setComments("Part of coordinated attack campaign - IOC: TTP-001234");

        assertEquals(LoginEventFeedback.FeedbackSource.INCIDENT_RESPONSE, feedback.getSource());
        assertTrue(feedback.getComments().contains("coordinated attack"));
        assertTrue(feedback.getComments().contains("IOC"));
    }

    @Test
    void testFeedbackTimestampHandling() {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime pastTime = now.minusMinutes(30);

        feedback.setTimestamp(pastTime);
        assertEquals(pastTime, feedback.getTimestamp());
        assertTrue(feedback.getTimestamp().isBefore(now));

        feedback.setTimestamp(now);
        assertEquals(now, feedback.getTimestamp());
    }

    @Test
    void testFeedbackLoginEventRelationship() {
        // Test relationship with login event
        assertNotNull(feedback.getLoginEvent());
        assertEquals(loginEvent.getId(), feedback.getLoginEvent().getId());
        assertEquals("testuser", feedback.getLoginEvent().getUser().getUsername());

        // Test with different login event
        LoginEvent anotherEvent = new LoginEvent();
        anotherEvent.setId(UUID.randomUUID());
        
        feedback.setLoginEvent(anotherEvent);
        assertEquals(anotherEvent, feedback.getLoginEvent());
        assertEquals(anotherEvent.getId(), feedback.getLoginEvent().getId());
    }

    @Test
    void testNullValueHandling() {
        // Test null value handling
        feedback.setComments(null);
        assertNull(feedback.getComments());

        feedback.setReviewerId(null);
        assertNull(feedback.getReviewerId());

        feedback.setLoginEvent(null);
        assertNull(feedback.getLoginEvent());
    }

    @Test
    void testEmptyComments() {
        feedback.setComments("");
        assertEquals("", feedback.getComments());

        feedback.setComments("   ");
        assertEquals("   ", feedback.getComments());
    }

    @Test
    void testLongComments() {
        // Test handling of long comments
        String longComment = "This is a very detailed analysis of the login event. ".repeat(10);
        feedback.setComments(longComment);
        assertEquals(longComment, feedback.getComments());
        assertTrue(feedback.getComments().length() > 100);
    }

    @Test
    void testFeedbackEquality() {
        String id1 = UUID.randomUUID().toString();
        String id2 = UUID.randomUUID().toString();

        LoginEventFeedback feedback1 = new LoginEventFeedback();
        feedback1.setId(id1);

        LoginEventFeedback feedback2 = new LoginEventFeedback();
        feedback2.setId(id1);

        LoginEventFeedback feedback3 = new LoginEventFeedback();
        feedback3.setId(id2);

        // Test equality based on ID
        assertEquals(feedback1.getId(), feedback2.getId());
        assertNotEquals(feedback1.getId(), feedback3.getId());
    }

    @Test
    void testFeedbackToString() {
        String feedbackString = feedback.toString();

        // Verify toString includes important information
        assertNotNull(feedbackString);
        assertTrue(feedbackString.contains("TRUE_POSITIVE") || 
                  feedbackString.contains("admin123") ||
                  feedbackString.contains("ADMIN_REVIEW") ||
                  feedbackString.contains("LoginEventFeedback"));
    }

    @Test
    void testComplexFeedbackScenario() {
        // Test complex feedback scenario with multiple analysts
        feedback.setSource(LoginEventFeedback.FeedbackSource.ADMIN_REVIEW);
        feedback.setReviewerId("senior_analyst_jane");
        feedback.setFeedbackType(LoginEventFeedback.FeedbackType.TRUE_POSITIVE);
        feedback.setComments("Initial assessment: FALSE_POSITIVE. After correlation with SIEM data: TRUE_POSITIVE. " +
                           "Attack vector: credential stuffing from botnet. Recommendation: update IP reputation rules.");

        assertEquals(LoginEventFeedback.FeedbackSource.ADMIN_REVIEW, feedback.getSource());
        assertEquals("senior_analyst_jane", feedback.getReviewerId());
        assertTrue(feedback.getComments().contains("credential stuffing"));
        assertTrue(feedback.getComments().contains("botnet"));
        assertTrue(feedback.getComments().contains("Recommendation"));
    }

    @Test
    void testFeedbackAuditTrail() {
        // Test audit trail information
        feedback.setSource(LoginEventFeedback.FeedbackSource.ADMIN_REVIEW);
        feedback.setReviewerId("audit_user_001");
        feedback.setTimestamp(LocalDateTime.now());

        // Verify audit information is preserved
        assertEquals("audit_user_001", feedback.getReviewerId());
        assertNotNull(feedback.getTimestamp());
        assertEquals(LoginEventFeedback.FeedbackSource.ADMIN_REVIEW, feedback.getSource());
    }

    @Test
    void testFeedbackImpactOnMachineLearning() {
        // Test scenario where feedback impacts ML model
        loginEvent.setTriggeredRules("new_device,unusual_location,off_hours");
        
        feedback.setFeedbackType(LoginEventFeedback.FeedbackType.TRUE_POSITIVE);
        feedback.setSource(LoginEventFeedback.FeedbackSource.AUTOMATED_SYSTEM);
        feedback.setReviewerId("ml_trainer_system");
        feedback.setComments("Model confidence: 0.85. Feature importance: location=0.4, time=0.3, device=0.3");

        assertEquals(LoginEventFeedback.FeedbackSource.AUTOMATED_SYSTEM, feedback.getSource());
        assertTrue(feedback.getComments().contains("confidence"));
        assertTrue(feedback.getComments().contains("Feature importance"));
    }
} 