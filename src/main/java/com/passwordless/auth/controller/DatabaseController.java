package com.passwordless.auth.controller;

import com.passwordless.auth.model.LoginEvent;
import com.passwordless.auth.model.User;
import com.passwordless.auth.repository.LoginEventRepository;
import com.passwordless.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.HashMap;

/**
 * REST controller for database inspection and statistics reporting.
 * Provides administrative endpoints for monitoring system data,
 * analyzing security event patterns, and generating operational metrics.
 * 
 * This controller is primarily intended for development, debugging,
 * and administrative oversight of the passwordless authentication system.
 */
@RestController
@RequestMapping("/api/database")
public class DatabaseController {

    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private LoginEventRepository loginEventRepository;

    /**
     * Retrieves all users in the system.
     * Administrative endpoint for user management and system overview.
     * 
     * @return List of all registered users
     */
    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userRepository.findAll();
        return ResponseEntity.ok(users);
    }

    /**
     * Retrieves all login events in the system.
     * Administrative endpoint for security audit and pattern analysis.
     * 
     * @return List of all recorded login events
     */
    @GetMapping("/login-events")
    public ResponseEntity<List<LoginEvent>> getAllLoginEvents() {
        List<LoginEvent> events = loginEventRepository.findAll();
        return ResponseEntity.ok(events);
    }
    
    /**
     * Retrieves login events for a specific user.
     * Used for user-specific security analysis and troubleshooting.
     * 
     * @param username Username to get login events for
     * @return List of login events for the specified user, or 404 if user not found
     */
    @GetMapping("/login-events/user/{username}")
    public ResponseEntity<List<LoginEvent>> getLoginEventsByUser(@PathVariable String username) {
        User user = userRepository.findByUsername(username).orElse(null);
        if (user == null) {
            return ResponseEntity.notFound().build();
        }
        List<LoginEvent> events = loginEventRepository.findByUserOrderByTimestampDesc(user);
        return ResponseEntity.ok(events);
    }
    
    /**
     * Generates comprehensive database statistics and security metrics.
     * Provides insights into system usage, security evaluation patterns,
     * and overall authentication activity for operational monitoring.
     * 
     * @return Map containing various system statistics and metrics
     */
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getDatabaseStats() {
        Map<String, Object> stats = new HashMap<>();
        
        // Basic entity counts
        stats.put("totalUsers", userRepository.count());
        stats.put("totalLoginEvents", loginEventRepository.count());
        
        // Security evaluation result distribution
        long allowCount = loginEventRepository.findAll().stream()
            .mapToLong(event -> event.getEvaluationResult() == LoginEvent.EvaluationResult.ALLOW ? 1 : 0)
            .sum();
        long redFlagCount = loginEventRepository.findAll().stream()
            .mapToLong(event -> event.getEvaluationResult() == LoginEvent.EvaluationResult.RED_FLAG ? 1 : 0)
            .sum();
        long denyCount = loginEventRepository.findAll().stream()
            .mapToLong(event -> event.getEvaluationResult() == LoginEvent.EvaluationResult.DENY ? 1 : 0)
            .sum();
            
        stats.put("allowedLogins", allowCount);
        stats.put("flaggedLogins", redFlagCount);
        stats.put("deniedLogins", denyCount);
        
        return ResponseEntity.ok(stats);
    }
} 