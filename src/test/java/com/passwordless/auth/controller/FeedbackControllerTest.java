package com.passwordless.auth.controller;

import com.passwordless.auth.model.LoginEvent;
import com.passwordless.auth.model.LoginEventFeedback;
import com.passwordless.auth.model.User;
import com.passwordless.auth.service.FeedbackLearningService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class FeedbackControllerTest {

    @Mock
    private FeedbackLearningService feedbackLearningService;

    @InjectMocks
    private FeedbackController feedbackController;

    private User testUser;
    private LoginEvent testLoginEvent;
    private UUID testLoginEventId;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        // Setup test user
        testUser = new User();
        testUser.setId(System.currentTimeMillis());
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
    void testTruePositiveFeedback() {
        // Setup
        LoginEventFeedback mockFeedback = new LoginEventFeedback();
        mockFeedback.setId(UUID.randomUUID().toString());
        when(feedbackLearningService.recordFeedback(
                any(UUID.class),
                eq(LoginEventFeedback.FeedbackType.TRUE_POSITIVE),
                eq(LoginEventFeedback.FeedbackSource.ADMIN_REVIEW),
                anyString(),
                anyString()
        )).thenReturn(mockFeedback);

        // Execute
        ResponseEntity<Map<String, Object>> response = feedbackController.markTruePositive(
                testLoginEventId,
                "admin1",
                "Confirmed legitimate login"
        );

        // Verify
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        Map<String, Object> body = response.getBody();
        assertNotNull(body);
        assertEquals("success", body.get("status"));
        assertEquals(mockFeedback.getId(), body.get("feedbackId"));

        // Verify service call
        verify(feedbackLearningService, times(1)).recordFeedback(
                eq(testLoginEventId),
                eq(LoginEventFeedback.FeedbackType.TRUE_POSITIVE),
                eq(LoginEventFeedback.FeedbackSource.ADMIN_REVIEW),
                eq("admin1"),
                eq("Confirmed legitimate login")
        );
    }

    @Test
    void testTrueNegativeFeedback() {
        // Setup
        LoginEventFeedback mockFeedback = new LoginEventFeedback();
        mockFeedback.setId(UUID.randomUUID().toString());
        when(feedbackLearningService.recordFeedback(
                any(UUID.class),
                eq(LoginEventFeedback.FeedbackType.TRUE_NEGATIVE),
                eq(LoginEventFeedback.FeedbackSource.ADMIN_REVIEW),
                anyString(),
                anyString()
        )).thenReturn(mockFeedback);

        // Execute
        ResponseEntity<Map<String, Object>> response = feedbackController.markTrueNegative(
                testLoginEventId,
                "admin1",
                "Confirmed unauthorized access attempt"
        );

        // Verify
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        Map<String, Object> body = response.getBody();
        assertNotNull(body);
        assertEquals("success", body.get("status"));
        assertEquals(mockFeedback.getId(), body.get("feedbackId"));

        // Verify service call
        verify(feedbackLearningService, times(1)).recordFeedback(
                eq(testLoginEventId),
                eq(LoginEventFeedback.FeedbackType.TRUE_NEGATIVE),
                eq(LoginEventFeedback.FeedbackSource.ADMIN_REVIEW),
                eq("admin1"),
                eq("Confirmed unauthorized access attempt")
        );
    }

    @Test
    void testDuplicateFeedback() {
        // Setup
        when(feedbackLearningService.recordFeedback(
                any(UUID.class),
                any(LoginEventFeedback.FeedbackType.class),
                any(LoginEventFeedback.FeedbackSource.class),
                anyString(),
                anyString()
        )).thenReturn(null);

        // Execute
        ResponseEntity<Map<String, Object>> response = feedbackController.markTruePositive(
                testLoginEventId,
                "admin1",
                "Test comment"
        );

        // Verify
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        Map<String, Object> body = response.getBody();
        assertNotNull(body);
        assertEquals("warning", body.get("status"));
        assertEquals("Feedback already exists for this login event", body.get("message"));
    }

    @Test
    void testInvalidLoginEventId() {
        // Setup
        when(feedbackLearningService.recordFeedback(
                any(UUID.class),
                any(LoginEventFeedback.FeedbackType.class),
                any(LoginEventFeedback.FeedbackSource.class),
                anyString(),
                anyString()
        )).thenThrow(new IllegalArgumentException("Login event not found"));

        // Execute
        ResponseEntity<Map<String, Object>> response = feedbackController.markTruePositive(
                UUID.randomUUID(),
                "admin1",
                "Test comment"
        );

        // Verify
        assertNotNull(response);
        assertEquals(400, response.getStatusCodeValue());
        Map<String, Object> body = response.getBody();
        assertNotNull(body);
        assertEquals("error", body.get("status"));
        assertEquals("Login event not found", body.get("message"));
    }

    @Test
    void testFlexibleFeedbackRecording() {
        // Setup
        LoginEventFeedback mockFeedback = new LoginEventFeedback();
        mockFeedback.setId(UUID.randomUUID().toString());
        when(feedbackLearningService.recordFeedback(
                any(UUID.class),
                any(LoginEventFeedback.FeedbackType.class),
                any(LoginEventFeedback.FeedbackSource.class),
                anyString(),
                anyString()
        )).thenReturn(mockFeedback);

        // Create feedback request
        FeedbackController.FeedbackRequest request = new FeedbackController.FeedbackRequest();
        request.setLoginEventId(testLoginEventId);
        request.setFeedbackType(LoginEventFeedback.FeedbackType.TRUE_POSITIVE);
        request.setSource(LoginEventFeedback.FeedbackSource.USER_REPORT);
        request.setReviewerId("user1");
        request.setComments("User confirmed legitimate login");

        // Execute
        ResponseEntity<Map<String, Object>> response = feedbackController.recordFeedback(request);

        // Verify
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        Map<String, Object> body = response.getBody();
        assertNotNull(body);
        assertEquals("success", body.get("status"));
        assertEquals(mockFeedback.getId(), body.get("feedbackId"));

        // Verify service call
        verify(feedbackLearningService, times(1)).recordFeedback(
                eq(testLoginEventId),
                eq(LoginEventFeedback.FeedbackType.TRUE_POSITIVE),
                eq(LoginEventFeedback.FeedbackSource.USER_REPORT),
                eq("user1"),
                eq("User confirmed legitimate login")
        );
    }

    @Test
    void testSystemGeneratedFeedback() {
        // Setup
        LoginEventFeedback mockFeedback = new LoginEventFeedback();
        mockFeedback.setId(UUID.randomUUID().toString());
        when(feedbackLearningService.recordFeedback(
                any(UUID.class),
                any(LoginEventFeedback.FeedbackType.class),
                any(LoginEventFeedback.FeedbackSource.class),
                anyString(),
                anyString()
        )).thenReturn(mockFeedback);

        // Execute with null reviewerId to test system-generated feedback
        ResponseEntity<Map<String, Object>> response = feedbackController.markTruePositive(
                testLoginEventId,
                null,
                "Automated system feedback"
        );

        // Verify
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        Map<String, Object> body = response.getBody();
        assertNotNull(body);
        assertEquals("success", body.get("status"));

        // Verify service call with system as reviewer
        verify(feedbackLearningService, times(1)).recordFeedback(
                eq(testLoginEventId),
                eq(LoginEventFeedback.FeedbackType.TRUE_POSITIVE),
                eq(LoginEventFeedback.FeedbackSource.ADMIN_REVIEW),
                eq("system"),
                eq("Automated system feedback")
        );
    }
}
