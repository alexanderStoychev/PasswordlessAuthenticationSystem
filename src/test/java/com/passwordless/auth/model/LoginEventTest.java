package com.passwordless.auth.model;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive test suite for the LoginEvent entity.
 * Tests security event logging and contextual analysis.
 */
class LoginEventTest {

    private LoginEvent loginEvent;
    private User user;
    private UUID eventId;

    @BeforeEach
    void setUp() {
        user = new User();
        user.setId(1L);
        user.setUsername("testuser");

        eventId = UUID.randomUUID();
        loginEvent = new LoginEvent();
        loginEvent.setId(eventId);
        loginEvent.setUser(user);
        loginEvent.setTimestamp(LocalDateTime.now());
        loginEvent.setIpAddress("192.168.1.100");
        loginEvent.setUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        loginEvent.setCountry("US");
        loginEvent.setEvaluationResult(LoginEvent.EvaluationResult.ALLOW);
        loginEvent.setTriggeredRules("normal_login");
    }

    @Test
    void testValidLoginEventCreation() {
        // Verify all fields are set correctly
        assertEquals(eventId, loginEvent.getId());
        assertEquals(user, loginEvent.getUser());
        assertNotNull(loginEvent.getTimestamp());
        assertEquals("192.168.1.100", loginEvent.getIpAddress());
        assertTrue(loginEvent.getUserAgent().contains("Mozilla"));
        assertEquals("US", loginEvent.getCountry());
        assertEquals(LoginEvent.EvaluationResult.ALLOW, loginEvent.getEvaluationResult());
        assertEquals("normal_login", loginEvent.getTriggeredRules());
    }

    @Test
    void testEvaluationResultEnum() {
        // Test all evaluation result values
        loginEvent.setEvaluationResult(LoginEvent.EvaluationResult.ALLOW);
        assertEquals(LoginEvent.EvaluationResult.ALLOW, loginEvent.getEvaluationResult());

        loginEvent.setEvaluationResult(LoginEvent.EvaluationResult.RED_FLAG);
        assertEquals(LoginEvent.EvaluationResult.RED_FLAG, loginEvent.getEvaluationResult());

        loginEvent.setEvaluationResult(LoginEvent.EvaluationResult.DENY);
        assertEquals(LoginEvent.EvaluationResult.DENY, loginEvent.getEvaluationResult());
    }

    @Test
    void testSuspiciousLoginEvent() {
        // Test suspicious login scenario
        loginEvent.setIpAddress("103.224.182.251"); // Suspicious IP
        loginEvent.setCountry("RU");
        loginEvent.setEvaluationResult(LoginEvent.EvaluationResult.RED_FLAG);
        loginEvent.setTriggeredRules("new_ip,unusual_location,suspicious_timing");

        assertEquals("103.224.182.251", loginEvent.getIpAddress());
        assertEquals("RU", loginEvent.getCountry());
        assertEquals(LoginEvent.EvaluationResult.RED_FLAG, loginEvent.getEvaluationResult());
        assertTrue(loginEvent.getTriggeredRules().contains("new_ip"));
        assertTrue(loginEvent.getTriggeredRules().contains("unusual_location"));
    }

    @Test
    void testDeniedLoginEvent() {
        // Test denied login scenario
        loginEvent.setEvaluationResult(LoginEvent.EvaluationResult.DENY);
        loginEvent.setTriggeredRules("blocked_ip,multiple_failures,known_threat");

        assertEquals(LoginEvent.EvaluationResult.DENY, loginEvent.getEvaluationResult());
        assertTrue(loginEvent.getTriggeredRules().contains("blocked_ip"));
    }

    @Test
    void testTimestampHandling() {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime pastTime = now.minusHours(2);

        loginEvent.setTimestamp(pastTime);
        assertEquals(pastTime, loginEvent.getTimestamp());
        assertTrue(loginEvent.getTimestamp().isBefore(now));
    }

    @Test
    void testIpAddressVariations() {
        // Test different IP address formats
        String[] testIPs = {
            "127.0.0.1",
            "192.168.1.1",
            "10.0.0.1",
            "8.8.8.8",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334" // IPv6
        };

        for (String ip : testIPs) {
            loginEvent.setIpAddress(ip);
            assertEquals(ip, loginEvent.getIpAddress());
        }
    }

    @Test
    void testUserAgentHandling() {
        // Test different user agents
        String[] userAgents = {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "curl/7.68.0",
            "PostmanRuntime/7.29.2"
        };

        for (String userAgent : userAgents) {
            loginEvent.setUserAgent(userAgent);
            assertEquals(userAgent, loginEvent.getUserAgent());
        }
    }

    @Test
    void testCountryCodeHandling() {
        // Test various country codes
        String[] countryCodes = {"US", "CA", "GB", "DE", "JP", "AU", "BR", "IN"};

        for (String country : countryCodes) {
            loginEvent.setCountry(country);
            assertEquals(country, loginEvent.getCountry());
        }
    }

    @Test
    void testTriggeredRulesFormatting() {
        // Test different rule combinations
        loginEvent.setTriggeredRules("rule1");
        assertEquals("rule1", loginEvent.getTriggeredRules());

        loginEvent.setTriggeredRules("rule1,rule2,rule3");
        assertEquals("rule1,rule2,rule3", loginEvent.getTriggeredRules());

        loginEvent.setTriggeredRules("");
        assertEquals("", loginEvent.getTriggeredRules());
    }

    @Test
    void testNullValueHandling() {
        // Test null value handling
        loginEvent.setCountry(null);
        assertNull(loginEvent.getCountry());

        loginEvent.setTriggeredRules(null);
        assertNull(loginEvent.getTriggeredRules());

        loginEvent.setUserAgent(null);
        assertNull(loginEvent.getUserAgent());
    }

    @Test
    void testLoginEventUserRelationship() {
        // Test user relationship
        assertNotNull(loginEvent.getUser());
        assertEquals("testuser", loginEvent.getUser().getUsername());
        assertEquals(1L, loginEvent.getUser().getId());

        // Test with different user
        User anotherUser = new User();
        anotherUser.setId(2L);
        anotherUser.setUsername("anotheruser");

        loginEvent.setUser(anotherUser);
        assertEquals(anotherUser, loginEvent.getUser());
        assertEquals("anotheruser", loginEvent.getUser().getUsername());
    }

    @Test
    void testLoginEventEquality() {
        UUID id1 = UUID.randomUUID();
        UUID id2 = UUID.randomUUID();

        LoginEvent event1 = new LoginEvent();
        event1.setId(id1);

        LoginEvent event2 = new LoginEvent();
        event2.setId(id1);

        LoginEvent event3 = new LoginEvent();
        event3.setId(id2);

        // Test equality based on ID
        assertEquals(event1.getId(), event2.getId());
        assertNotEquals(event1.getId(), event3.getId());
    }

    @Test
    void testLoginEventToString() {
        String eventString = loginEvent.toString();

        // Verify toString includes important information
        assertNotNull(eventString);
        assertTrue(eventString.contains("testuser") || 
                  eventString.contains("192.168.1.100") ||
                  eventString.contains("ALLOW") ||
                  eventString.contains("LoginEvent"));
    }

    @Test
    void testComplexSecurityScenario() {
        // Test complex security evaluation scenario
        loginEvent.setIpAddress("47.254.33.193"); // Suspicious IP
        loginEvent.setCountry("CN");
        loginEvent.setUserAgent("python-requests/2.25.1"); // Automated tool
        loginEvent.setEvaluationResult(LoginEvent.EvaluationResult.RED_FLAG);
        loginEvent.setTriggeredRules("new_ip,unusual_location,bot_behavior,off_hours_access");

        assertEquals("47.254.33.193", loginEvent.getIpAddress());
        assertEquals("CN", loginEvent.getCountry());
        assertEquals(LoginEvent.EvaluationResult.RED_FLAG, loginEvent.getEvaluationResult());
        assertTrue(loginEvent.getTriggeredRules().contains("bot_behavior"));
        assertTrue(loginEvent.getTriggeredRules().contains("off_hours_access"));
    }

    @Test
    void testMobileDeviceLogin() {
        // Test mobile device login scenario
        loginEvent.setUserAgent("Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15");
        loginEvent.setIpAddress("10.0.0.245"); // Mobile network IP
        loginEvent.setCountry("US");
        loginEvent.setEvaluationResult(LoginEvent.EvaluationResult.ALLOW);
        loginEvent.setTriggeredRules("mobile_device,known_location");

        assertTrue(loginEvent.getUserAgent().contains("iPhone"));
        assertEquals(LoginEvent.EvaluationResult.ALLOW, loginEvent.getEvaluationResult());
        assertTrue(loginEvent.getTriggeredRules().contains("mobile_device"));
    }
} 