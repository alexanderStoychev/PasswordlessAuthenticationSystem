package com.passwordless.auth.repository;

import com.passwordless.auth.model.LoginEvent;
import com.passwordless.auth.model.LoginEventFeedback;
import com.passwordless.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Repository interface for LoginEventFeedback entity data access operations.
 * Provides specialized queries for machine learning feedback analysis,
 * performance metrics, and adaptive security system optimization.
 */
@Repository
public interface LoginEventFeedbackRepository extends JpaRepository<LoginEventFeedback, String> {
    
    /**
     * Retrieves all feedback records for a specific login event.
     * Used to check existing feedback and prevent duplicates.
     * 
     * @param loginEvent The login event to find feedback for
     * @return List of feedback records for the specified login event
     */
    List<LoginEventFeedback> findByLoginEvent(LoginEvent loginEvent);
    
    /**
     * Retrieves feedback records by type (TRUE_POSITIVE/TRUE_NEGATIVE).
     * Used for analyzing the distribution of feedback types and system accuracy.
     * 
     * @param feedbackType Type of feedback to search for
     * @return List of feedback records of the specified type
     */
    List<LoginEventFeedback> findByFeedbackType(LoginEventFeedback.FeedbackType feedbackType);
    
    /**
     * Retrieves feedback records by source (admin, user, automated, etc.).
     * Used for weighting feedback credibility and analyzing source reliability.
     * 
     * @param source Source of the feedback to search for
     * @return List of feedback records from the specified source
     */
    List<LoginEventFeedback> findBySource(LoginEventFeedback.FeedbackSource source);
    
    /**
     * Retrieves feedback records within a specific time range.
     * Used for generating time-based performance reports and trend analysis.
     * 
     * @param start Start of the time range
     * @param end End of the time range
     * @return List of feedback records within the specified time range
     */
    List<LoginEventFeedback> findByTimestampBetween(LocalDateTime start, LocalDateTime end);
    
    /**
     * Aggregates feedback statistics by type for a specific user.
     * Provides insights into per-user feedback patterns and personalization data
     * for the machine learning system.
     * 
     * @param user User to generate statistics for
     * @param since Cutoff date for recent feedback
     * @return Array of [feedbackType, count] tuples
     */
    @Query("SELECT f.feedbackType, COUNT(f) FROM LoginEventFeedback f " +
           "WHERE f.loginEvent.user = :user AND f.timestamp >= :since " +
           "GROUP BY f.feedbackType")
    List<Object[]> getFeedbackStatsByUser(@Param("user") User user, @Param("since") LocalDateTime since);
    
    /**
     * Calculates feedback statistics for specific security rules.
     * Critical for measuring rule effectiveness and adjusting weights
     * in the adaptive security system.
     * 
     * @param rule Security rule name to analyze
     * @param since Cutoff date for recent feedback
     * @return Array of [feedbackType, count] tuples for the specified rule
     */
    @Query("SELECT f.feedbackType, COUNT(f) FROM LoginEventFeedback f " +
           "WHERE f.loginEvent.triggeredRules LIKE %:rule% AND f.timestamp >= :since " +
           "GROUP BY f.feedbackType")
    List<Object[]> getFeedbackStatsForRule(@Param("rule") String rule, @Param("since") LocalDateTime since);
    
    /**
     * Retrieves recent feedback for machine learning model updates.
     * Used by the learning system to incorporate new feedback into
     * rule weight adjustments and performance improvements.
     * 
     * @param since Cutoff date for "recent" feedback
     * @return List of recent feedback records ordered by timestamp descending
     */
    @Query("SELECT f FROM LoginEventFeedback f " +
           "WHERE f.timestamp >= :since " +
           "ORDER BY f.timestamp DESC")
    List<LoginEventFeedback> findRecentFeedback(@Param("since") LocalDateTime since);
    
    /**
     * Checks if feedback already exists for a specific login event.
     * Prevents duplicate feedback entries which could skew learning algorithms
     * and ensures data integrity in the feedback system.
     * 
     * @param loginEvent The login event to check for existing feedback
     * @return true if feedback exists, false otherwise
     */
    boolean existsByLoginEvent(LoginEvent loginEvent);
    

} 