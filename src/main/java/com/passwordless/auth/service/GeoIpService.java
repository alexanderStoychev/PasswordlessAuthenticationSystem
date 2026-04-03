package com.passwordless.auth.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.RestClientException;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Service for resolving geographic location information from IP addresses.
 * Used for contextual security analysis to detect logins from unusual locations.
 * 
 * Integrates with external IP geolocation services to provide country-level
 * location data while handling edge cases like private networks and localhost.
 */
@Service
public class GeoIpService {
    
    private static final Logger logger = LoggerFactory.getLogger(GeoIpService.class);
    
    /** REST client for making requests to IP geolocation APIs */
    private final RestTemplate restTemplate;
    
    /**
     * Constructor initializes the REST client for external API calls.
     */
    public GeoIpService() {
        this.restTemplate = new RestTemplate();
    }
    
    /**
     * Resolves country name from an IP address using external geolocation services.
     * Handles special cases for local and private network addresses.
     * 
     * @param ipAddress IP address to resolve location for
     * @return Country name, "Local" for private IPs, or "Unknown" if resolution fails
     */
    public String getCountryByIp(String ipAddress) {
        try {
            // Handle localhost and private network addresses
            if (isLocalOrPrivateIp(ipAddress)) {
                return "Local";
            }
            
            // Query external IP geolocation service
            String url = "https://ipapi.co/" + ipAddress + "/json/";
            GeoIpResponse response = restTemplate.getForObject(url, GeoIpResponse.class);
            
            if (response != null && response.getCountryName() != null) {
                return response.getCountryName();
            }
            
            return "Unknown";
        } catch (RestClientException e) {
            logger.warn("Failed to get country for IP {}: {}", ipAddress, e.getMessage());
            return "Unknown";
        }
    }
    
    /**
     * Determines if an IP address is localhost or within private network ranges.
     * Private network ranges include:
     * - IPv4: 127.0.0.1 (localhost), 192.168.x.x, 10.x.x.x, 172.16-31.x.x
     * - IPv6: ::1 (localhost)
     * 
     * @param ip IP address to check
     * @return true if the IP is localhost or in a private network range
     */
    private boolean isLocalOrPrivateIp(String ip) {
        return ip.equals("127.0.0.1") ||      // IPv4 localhost
               ip.equals("0:0:0:0:0:0:0:1") || // IPv6 localhost (full form)
               ip.equals("::1") ||             // IPv6 localhost (compressed)
               ip.startsWith("192.168.") ||    // Private Class C networks
               ip.startsWith("10.") ||         // Private Class A networks
               ip.startsWith("172.");          // Private Class B networks (simplified check)
    }
    
    /**
     * Data transfer object for IP geolocation API responses.
     * Uses Jackson annotations to handle unknown fields gracefully.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class GeoIpResponse {
        /** Country name from the API response */
        private String country_name;
        
        public String getCountryName() { 
            return country_name; 
        }
        
        public void setCountryName(String country_name) { 
            this.country_name = country_name; 
        }
    }
} 