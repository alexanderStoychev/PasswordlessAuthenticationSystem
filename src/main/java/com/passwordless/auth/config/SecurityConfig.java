package com.passwordless.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

/**
 * Spring Security configuration for the passwordless authentication system.
 * Configures web security policies, CORS settings, and endpoint access controls
 * to support the WebAuthn-based authentication and security analysis features.
 * 
 * This configuration:
 * - Permits public access to authentication and API endpoints
 * - Disables CSRF for API-only usage
 * - Configures CORS for frontend integration
 * - Allows H2 console access for development
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Configures the main security filter chain for HTTP requests.
     * Sets up authentication requirements, CORS handling, and endpoint permissions.
     * 
     * @param http HttpSecurity configuration object
     * @return Configured SecurityFilterChain
     * @throws Exception if configuration fails
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Enable CORS with custom configuration
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                
                // Disable CSRF protection (appropriate for API-only applications)
                .csrf(csrf -> csrf.disable())
                
                // Configure endpoint access permissions
                .authorizeHttpRequests(authorize -> authorize
                        // WebAuthn authentication endpoints - public access
                        .requestMatchers("/api/webauthn/**").permitAll()
                        
                        // Machine learning feedback endpoints - public access
                        .requestMatchers("/api/feedback/**").permitAll()
                        
                        // Database management endpoints - public access (development)
                        .requestMatchers("/api/database/**").permitAll()
                        
                        // Debug and monitoring endpoints - public access (development)
                        .requestMatchers("/api/debug/**").permitAll()
                        
                        // Security experiment endpoints - public access (research)
                        .requestMatchers("/api/experiments/**").permitAll()
                        
                        // User warning management endpoints - public access
                        .requestMatchers("/api/warnings/**").permitAll()
                        
                        // H2 database console - public access (development only)
                        .requestMatchers("/h2-console/**").permitAll()
                        
                        // All other requests require authentication
                        .anyRequest().authenticated()
                )
                
                // Disable frame options to allow H2 console embedding
                .headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()));

        return http.build();
    }

    /**
     * Configures CORS (Cross-Origin Resource Sharing) settings for frontend integration.
     * Allows the React frontend to communicate with the Spring Boot backend
     * across different ports during development.
     * 
     * @return CORS configuration source with allowed origins, methods, and headers
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // Allow specific development origins (React dev server, Spring Boot, alternative ports)
        configuration.setAllowedOrigins(Arrays.asList(
                "http://localhost:3000",  // React development server
                "http://localhost:8080",  // Spring Boot default port
                "http://localhost:3001"   // Alternative React port
        ));
        
        // Allow all common HTTP methods needed for RESTful APIs
        configuration.setAllowedMethods(Arrays.asList(
                "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
        ));
        
        // Allow all headers (including custom authentication headers)
        configuration.setAllowedHeaders(Arrays.asList("*"));
        
        // Expose authentication token header to frontend
        configuration.setExposedHeaders(Arrays.asList("x-auth-token"));
        
        // Allow credentials (cookies, authorization headers)
        configuration.setAllowCredentials(true);
        
        // Apply CORS configuration to all endpoints
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
} 