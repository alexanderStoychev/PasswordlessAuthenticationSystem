package com.passwordless.auth.config;

import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import com.passwordless.auth.repository.CredentialRepositoryImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.List;
import java.util.Set;

/**
 * Spring configuration for WebAuthn components.
 * Sets up the Relying Party configuration for biometric authentication.
 */
@Configuration
public class WebAuthnConfig {

    /** Relying Party identifier - must match the domain for production use */
    private static final String RP_ID = "localhost";
    
    /** Human-readable name for this relying party */
    private static final String RP_NAME = "Passwordless Auth Demo";

    @Autowired
    private CredentialRepositoryImpl credentialRepository;

    /**
     * Creates and configures the WebAuthn RelyingParty bean.
     * This is the core component that handles WebAuthn operations.
     * 
     * @return Configured RelyingParty instance
     */
    @Bean
    public RelyingParty relyingParty() {
        RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
            .id(RP_ID)
            .name(RP_NAME)
            .build();

        return RelyingParty.builder()
            .identity(rpIdentity)
            .credentialRepository(credentialRepository)
            // Allow connections from development and production origins
            .origins(Set.of("http://localhost:8080", "http://localhost:3000", "http://localhost:3001"))
            // Prefer ES256 algorithm for better compatibility
            .preferredPubkeyParams(List.of(
                PublicKeyCredentialParameters.builder()
                    .alg(COSEAlgorithmIdentifier.ES256)
                    .build()
            ))
            // Allow self-signed attestations for demo purposes
            .allowUntrustedAttestation(true)
            .build();
    }
} 