package com.passwordless.auth.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive test suite for the GeoIpService.
 * Tests IP geolocation resolution and edge case handling.
 */
class GeoIpServiceTest {

    @Mock
    private RestTemplate restTemplate;

    private GeoIpService geoIpService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        // Manually create service with mocked RestTemplate using reflection
        geoIpService = new GeoIpService();
        // Set the mocked RestTemplate using reflection
        try {
            java.lang.reflect.Field field = GeoIpService.class.getDeclaredField("restTemplate");
            field.setAccessible(true);
            field.set(geoIpService, restTemplate);
        } catch (Exception e) {
            throw new RuntimeException("Failed to inject mock RestTemplate", e);
        }
    }

    @Test
    void testLocalhostIpDetection() {
        // Test IPv4 localhost
        String result = geoIpService.getCountryByIp("127.0.0.1");
        assertEquals("Local", result);

        // Test IPv6 localhost variants
        result = geoIpService.getCountryByIp("::1");
        assertEquals("Local", result);

        result = geoIpService.getCountryByIp("0:0:0:0:0:0:0:1");
        assertEquals("Local", result);

        // Verify no external API calls were made
        verifyNoInteractions(restTemplate);
    }

    @Test
    void testPrivateNetworkIpDetection() {
        // Test Class A private networks (10.x.x.x)
        String result = geoIpService.getCountryByIp("10.0.0.1");
        assertEquals("Local", result);

        result = geoIpService.getCountryByIp("10.255.255.255");
        assertEquals("Local", result);

        // Test Class B private networks (172.16-31.x.x)
        result = geoIpService.getCountryByIp("172.16.0.1");
        assertEquals("Local", result);

        result = geoIpService.getCountryByIp("172.31.255.255");
        assertEquals("Local", result);

        // Test Class C private networks (192.168.x.x)
        result = geoIpService.getCountryByIp("192.168.1.1");
        assertEquals("Local", result);

        result = geoIpService.getCountryByIp("192.168.255.255");
        assertEquals("Local", result);

        // Verify no external API calls were made
        verifyNoInteractions(restTemplate);
    }

    @Test
    void testPublicIpResolution() {
        // Setup mock response
        GeoIpService.GeoIpResponse mockResponse = new GeoIpService.GeoIpResponse();
        mockResponse.setCountryName("United States");

        when(restTemplate.getForObject(anyString(), eq(GeoIpService.GeoIpResponse.class)))
            .thenReturn(mockResponse);

        // Test public IP resolution
        String result = geoIpService.getCountryByIp("8.8.8.8");
        assertEquals("United States", result);

        // Verify API was called
        verify(restTemplate).getForObject(
            eq("https://ipapi.co/8.8.8.8/json/"), 
            eq(GeoIpService.GeoIpResponse.class)
        );
    }

    @Test
    void testMultiplePublicIpResolutions() {
        // Setup mock responses for different countries
        GeoIpService.GeoIpResponse usResponse = new GeoIpService.GeoIpResponse();
        usResponse.setCountryName("United States");

        GeoIpService.GeoIpResponse ukResponse = new GeoIpService.GeoIpResponse();
        ukResponse.setCountryName("United Kingdom");

        GeoIpService.GeoIpResponse cnResponse = new GeoIpService.GeoIpResponse();
        cnResponse.setCountryName("China");

        when(restTemplate.getForObject(eq("https://ipapi.co/8.8.8.8/json/"), eq(GeoIpService.GeoIpResponse.class)))
            .thenReturn(usResponse);
        when(restTemplate.getForObject(eq("https://ipapi.co/1.1.1.1/json/"), eq(GeoIpService.GeoIpResponse.class)))
            .thenReturn(ukResponse);
        when(restTemplate.getForObject(eq("https://ipapi.co/114.114.114.114/json/"), eq(GeoIpService.GeoIpResponse.class)))
            .thenReturn(cnResponse);

        // Test multiple IP resolutions
        assertEquals("United States", geoIpService.getCountryByIp("8.8.8.8"));
        assertEquals("United Kingdom", geoIpService.getCountryByIp("1.1.1.1"));
        assertEquals("China", geoIpService.getCountryByIp("114.114.114.114"));

        // Verify all API calls were made
        verify(restTemplate, times(3)).getForObject(anyString(), eq(GeoIpService.GeoIpResponse.class));
    }

    @Test
    void testApiFailureHandling() {
        // Setup API failure
        when(restTemplate.getForObject(anyString(), eq(GeoIpService.GeoIpResponse.class)))
            .thenThrow(new RestClientException("API unavailable"));

        // Test failure handling
        String result = geoIpService.getCountryByIp("8.8.8.8");
        assertEquals("Unknown", result);

        // Verify API was called
        verify(restTemplate).getForObject(anyString(), eq(GeoIpService.GeoIpResponse.class));
    }

    @Test
    void testNullResponseHandling() {
        // Setup null response
        when(restTemplate.getForObject(anyString(), eq(GeoIpService.GeoIpResponse.class)))
            .thenReturn(null);

        // Test null response handling
        String result = geoIpService.getCountryByIp("8.8.8.8");
        assertEquals("Unknown", result);
    }

    @Test
    void testEmptyCountryNameHandling() {
        // Setup response with null country name
        GeoIpService.GeoIpResponse mockResponse = new GeoIpService.GeoIpResponse();
        mockResponse.setCountryName(null);

        when(restTemplate.getForObject(anyString(), eq(GeoIpService.GeoIpResponse.class)))
            .thenReturn(mockResponse);

        // Test empty country name handling
        String result = geoIpService.getCountryByIp("8.8.8.8");
        assertEquals("Unknown", result);
    }

    @Test
    void testApiUrlConstruction() {
        // Setup mock response
        GeoIpService.GeoIpResponse mockResponse = new GeoIpService.GeoIpResponse();
        mockResponse.setCountryName("Test Country");

        when(restTemplate.getForObject(anyString(), eq(GeoIpService.GeoIpResponse.class)))
            .thenReturn(mockResponse);

        // Test API URL construction
        geoIpService.getCountryByIp("203.0.113.1");

        // Verify correct URL was called
        verify(restTemplate).getForObject(
            eq("https://ipapi.co/203.0.113.1/json/"), 
            eq(GeoIpService.GeoIpResponse.class)
        );
    }

    @Test
    void testEdgeCaseIpAddresses() {
        // Test broadcast address
        String result = geoIpService.getCountryByIp("255.255.255.255");
        // Should be treated as public IP and attempt API call
        assertNotNull(result);

        // Test zero address
        result = geoIpService.getCountryByIp("0.0.0.0");
        // Should be treated as public IP and attempt API call
        assertNotNull(result);
    }

    @Test
    void testMalformedIpHandling() {
        // Setup API failure for malformed IP
        when(restTemplate.getForObject(anyString(), eq(GeoIpService.GeoIpResponse.class)))
            .thenThrow(new RestClientException("Invalid IP format"));

        // Test malformed IP handling
        String result = geoIpService.getCountryByIp("invalid.ip.address");
        assertEquals("Unknown", result);
    }

    @Test
    void testGeoIpResponseObject() {
        // Test GeoIpResponse object functionality
        GeoIpService.GeoIpResponse response = new GeoIpService.GeoIpResponse();
        
        // Test initial state
        assertNull(response.getCountryName());
        
        // Test setting country name
        response.setCountryName("Canada");
        assertEquals("Canada", response.getCountryName());
        
        // Test setting null country name
        response.setCountryName(null);
        assertNull(response.getCountryName());
        
        // Test setting empty country name
        response.setCountryName("");
        assertEquals("", response.getCountryName());
    }

    @Test
    void testConcurrentIpResolution() {
        // Setup mock response
        GeoIpService.GeoIpResponse mockResponse = new GeoIpService.GeoIpResponse();
        mockResponse.setCountryName("Germany");

        when(restTemplate.getForObject(anyString(), eq(GeoIpService.GeoIpResponse.class)))
            .thenReturn(mockResponse);

        // Test multiple concurrent-like calls
        String result1 = geoIpService.getCountryByIp("1.2.3.4");
        String result2 = geoIpService.getCountryByIp("5.6.7.8");
        String result3 = geoIpService.getCountryByIp("9.10.11.12");

        // All should return the same mocked response
        assertEquals("Germany", result1);
        assertEquals("Germany", result2);
        assertEquals("Germany", result3);

        // Verify all API calls were made
        verify(restTemplate, times(3)).getForObject(anyString(), eq(GeoIpService.GeoIpResponse.class));
    }

    @Test
    void testCountryNameWithSpecialCharacters() {
        // Setup response with special characters
        GeoIpService.GeoIpResponse mockResponse = new GeoIpService.GeoIpResponse();
        mockResponse.setCountryName("Côte d'Ivoire");

        when(restTemplate.getForObject(anyString(), eq(GeoIpService.GeoIpResponse.class)))
            .thenReturn(mockResponse);

        // Test special characters in country name
        String result = geoIpService.getCountryByIp("8.8.8.8");
        assertEquals("Côte d'Ivoire", result);
    }

    @Test
    void testLongCountryName() {
        // Setup response with long country name
        GeoIpService.GeoIpResponse mockResponse = new GeoIpService.GeoIpResponse();
        mockResponse.setCountryName("The United Kingdom of Great Britain and Northern Ireland");

        when(restTemplate.getForObject(anyString(), eq(GeoIpService.GeoIpResponse.class)))
            .thenReturn(mockResponse);

        // Test long country name
        String result = geoIpService.getCountryByIp("8.8.8.8");
        assertEquals("The United Kingdom of Great Britain and Northern Ireland", result);
    }
} 