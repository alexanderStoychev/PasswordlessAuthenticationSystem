package com.passwordless.auth.controller;

import com.passwordless.auth.model.LoginEvent;
import com.passwordless.auth.model.LoginEventFeedback;
import com.passwordless.auth.model.User;
import com.passwordless.auth.repository.LoginEventRepository;
import com.passwordless.auth.repository.UserRepository;
import com.passwordless.auth.service.FeedbackLearningService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * REST controller for managing security warnings and user self-service feedback.
 * Enables users to review flagged login attempts and provide feedback to improve
 * the machine learning system while maintaining security awareness.
 * 
 * This controller supports:
 * - Displaying pending security warnings to users
 * - Allowing users to confirm legitimate activity
 * - Reporting potential security incidents
 * - Feeding user responses back into the learning system
 */
@RestController
@RequestMapping("/api/warnings")
public class WarningController {

    @Autowired private UserRepository userRepo;
    @Autowired private LoginEventRepository eventRepo;
    @Autowired private FeedbackLearningService feedbackSvc;

    /**
     * Retrieves pending security warnings for a specific user.
     * Returns login events that have been flagged as suspicious (RED_FLAG)
     * and require user review or confirmation.
     * 
     * @param username Username to fetch warnings for
     * @return List of pending warnings requiring user attention
     */
    @GetMapping("/{username}")
    public ResponseEntity<List<PendingWarning>> pending(@PathVariable String username) {
        User user = userRepo.findByUsername(username).orElse(null);
        if (user == null) return ResponseEntity.notFound().build();

        List<PendingWarning> list = eventRepo.findUnreviewedFlags(user, LoginEvent.EvaluationResult.RED_FLAG).stream()
                .map(PendingWarning::from)
                .toList();

        return ResponseEntity.ok(list);
    }

    /**
     * Retrieves historical unreviewed security warnings for a user.
     * Shows previously flagged activities that haven't been resolved,
     * helping users catch up on security alerts they may have missed.
     * 
     * @param username Username to fetch historical warnings for
     * @return List of previous unreviewed security warnings
     */
    @GetMapping("/previous/{username}")
    public ResponseEntity<List<PendingWarning>> previousWarnings(@PathVariable String username) {
        User user = userRepo.findByUsername(username).orElse(null);
        if (user == null) return ResponseEntity.notFound().build();

        List<PendingWarning> list = eventRepo.findPreviousUnreviewedFlags(user, LoginEvent.EvaluationResult.RED_FLAG).stream()
                .map(PendingWarning::from)
                .toList();

        return ResponseEntity.ok(list);
    }

    /**
     * Allows users to resolve security warnings by providing feedback.
     * Users can confirm legitimate activity or report potential intrusions,
     * which feeds back into the machine learning system for improvement.
     * 
     * @param eventId ID of the login event being resolved
     * @param res User's resolution choice (TRUST or REPORT_INTRUSION)
     * @return Success response when feedback is recorded
     */
    @PostMapping("/{eventId}/resolve")
    public ResponseEntity<Void> resolve(@PathVariable UUID eventId,
                                        @RequestParam Resolution res) {

        // Convert user resolution to machine learning feedback:
        // TRUST → "Yes, it was me" → System correctly allowed (TRUE_POSITIVE)
        // REPORT_INTRUSION → "No, wasn't me" → System should have blocked (TRUE_NEGATIVE)
        feedbackSvc.recordFeedback(
                eventId,
                res == Resolution.TRUST
                        ? LoginEventFeedback.FeedbackType.TRUE_POSITIVE
                        : LoginEventFeedback.FeedbackType.TRUE_NEGATIVE,
                LoginEventFeedback.FeedbackSource.USER_REPORT,
                "self_service",
                null
        );

        return ResponseEntity.ok().build();
    }

    /**
     * Enumeration of user resolution choices for security warnings.
     * Represents the user's assessment of whether flagged activity was legitimate.
     */
    public enum Resolution { 
        /** User confirms the activity was legitimate - reduces future false positives */
        TRUST, 
        
        /** User reports potential intrusion - strengthens security rules */
        REPORT_INTRUSION 
    }

    /**
     * Data transfer object representing a pending security warning.
     * Contains essential information about flagged login attempts for user review.
     * 
     * @param id Unique identifier of the login event
     * @param timestamp When the suspicious activity occurred
     * @param ipAddress Source IP address of the login attempt
     * @param country Geographic location resolved from IP
     * @param triggeredRules JSON string of security rules that were triggered
     */
    public record PendingWarning(UUID id,
                                 String timestamp,
                                 String ipAddress,
                                 String country,
                                 String triggeredRules) {
        
        /**
         * Factory method to create PendingWarning from LoginEvent entity.
         * Extracts relevant fields for user-facing warning display.
         * 
         * @param e LoginEvent entity to convert
         * @return PendingWarning DTO with user-relevant information
         */
        static PendingWarning from(LoginEvent e) {
            return new PendingWarning(
                    e.getId(),
                    e.getTimestamp().toString(),
                    e.getIpAddress(),
                    e.getCountry(),
                    e.getTriggeredRules()
            );
        }
    }
}
