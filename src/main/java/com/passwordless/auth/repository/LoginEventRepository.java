package com.passwordless.auth.repository;

import com.passwordless.auth.model.LoginEvent;
import com.passwordless.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Repository interface for LoginEvent entity data access operations.
 * Provides specialized queries for security analysis, threat detection,
 * and user activity monitoring in the contextual authentication system.
 */
@Repository
public interface LoginEventRepository extends JpaRepository<LoginEvent, UUID> {
    
    /**
     * Retrieves all login events for a user, ordered by most recent first.
     * Used for user activity history and security timeline analysis.
     * 
     * @param user User to get login events for
     * @return List of login events ordered by timestamp descending
     */
    List<LoginEvent> findByUserOrderByTimestampDesc(User user);
    
    /**
     * Retrieves all login events from a specific IP address.
     * Used for IP reputation analysis and cross-user threat correlation.
     * 
     * @param ipAddress IP address to search for
     * @return List of login events from that IP, ordered by timestamp descending
     */
    List<LoginEvent> findByIpAddressOrderByTimestampDesc(String ipAddress);
    
    /**
     * Retrieves login events for a user with specific evaluation results.
     * Used for filtering events by security decision (ALLOW/RED_FLAG/DENY).
     * 
     * @param user User to search for
     * @param evaluationResult Security evaluation result to filter by
     * @return List of matching login events ordered by timestamp descending
     */
    List<LoginEvent> findByUserAndEvaluationResultOrderByTimestampDesc(User user, LoginEvent.EvaluationResult evaluationResult);

    /**
     * Finds security-flagged login events that haven't received feedback yet.
     * Critical for the machine learning system to identify pending review items
     * and for user notification of suspicious activities.
     * 
     * @param user User to search for unreviewed flags
     * @param flag Evaluation result to search for (typically RED_FLAG)
     * @return List of flagged events without feedback, ordered by timestamp descending
     */
    @Query("""
   SELECT le FROM LoginEvent le
   WHERE le.user = :user
     AND le.evaluationResult = :flag
     AND NOT EXISTS (
          SELECT f FROM LoginEventFeedback f
          WHERE f.loginEvent = le
     )
   ORDER BY le.timestamp DESC
   """)
    List<LoginEvent> findUnreviewedFlags(@Param("user") User user,
                                         @Param("flag") LoginEvent.EvaluationResult flag);

    /**
     * Retrieves recent login events for a user within a time window.
     * Essential for contextual analysis algorithms that detect patterns
     * like rapid successive logins or unusual activity bursts.
     * 
     * @param user User to search for recent activity
     * @param since Cutoff timestamp for "recent" events
     * @return List of login events since the specified time, ordered by timestamp descending
     */
    @Query("SELECT le FROM LoginEvent le WHERE le.user = :user AND le.timestamp >= :since ORDER BY le.timestamp DESC")
    List<LoginEvent> findRecentLoginsByUser(@Param("user") User user, @Param("since") LocalDateTime since);
    
    /**
     * Gets all distinct IP addresses a user has logged in from.
     * Used for building user IP profiles and detecting new location logins.
     * 
     * @param user User to get IP address history for
     * @return List of unique IP addresses used by the user
     */
    @Query("SELECT DISTINCT le.ipAddress FROM LoginEvent le WHERE le.user = :user")
    List<String> findDistinctIpAddressesByUser(@Param("user") User user);
    
    /**
     * Counts login events for a specific user-IP combination.
     * Used for trust scoring and determining established vs. new IP patterns.
     * 
     * @param user User to count events for
     * @param ipAddress IP address to count events for
     * @return Number of login events for this user-IP combination
     */
    @Query("SELECT COUNT(le) FROM LoginEvent le WHERE le.user = :user AND le.ipAddress = :ipAddress")
    Long countByUserAndIpAddress(@Param("user") User user, @Param("ipAddress") String ipAddress);

    /**
     * Finds historical unreviewed security flags excluding the most recent login.
     * Used for showing users past security alerts they may have missed,
     * excluding the current session to avoid confusion.
     * 
     * @param user User to search for historical flags
     * @param flag Evaluation result to search for (typically RED_FLAG)
     * @return List of historical flagged events without feedback, ordered by timestamp descending
     */
    @Query("""
   SELECT le FROM LoginEvent le
   WHERE le.user = :user
     AND le.evaluationResult = :flag
     AND NOT EXISTS (
          SELECT f FROM LoginEventFeedback f
          WHERE f.loginEvent = le
     )
     AND le.timestamp < (
          SELECT MAX(le2.timestamp)
          FROM LoginEvent le2
          WHERE le2.user = :user
     )
   ORDER BY le.timestamp DESC
   """)
    List<LoginEvent> findPreviousUnreviewedFlags(@Param("user") User user,
                                                 @Param("flag") LoginEvent.EvaluationResult flag);
} 