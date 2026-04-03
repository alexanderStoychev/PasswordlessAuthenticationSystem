package com.passwordless.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

/**
 * Configuration for HTTP client beans used for external API integration.
 * Provides RestTemplate instances for making HTTP requests to external services
 * such as IP geolocation APIs and other third-party security services.
 */
@Configuration
public class RestTemplateConfig {
    
    /**
     * Creates a RestTemplate bean for HTTP client operations.
     * Used by services like GeoIpService to query external APIs for
     * geographic location data and other contextual information.
     * 
     * @return Configured RestTemplate instance for dependency injection
     */
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}