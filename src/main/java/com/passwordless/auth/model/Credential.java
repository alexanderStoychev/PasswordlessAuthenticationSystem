package com.passwordless.auth.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;

/**
 * JPA entity representing a WebAuthn credential stored for a user.
 * Contains the cryptographic data needed to verify biometric authentication attempts.
 */
@Entity
public class Credential {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** User account associated with this credential */
    @ManyToOne
    private User user;

    /** Base64-encoded unique identifier for this specific credential */
    private String credentialId;
    
    /** Base64-encoded public key in COSE format for signature verification */
    private String publicKeyCose;
    
    /** Signature counter used to detect cloned authenticators */
    private Long signatureCount;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getCredentialId() {
        return credentialId;
    }

    public void setCredentialId(String credentialId) {
        this.credentialId = credentialId;
    }

    public String getPublicKeyCose() {
        return publicKeyCose;
    }

    public void setPublicKeyCose(String publicKeyCose) {
        this.publicKeyCose = publicKeyCose;
    }

    public Long getSignatureCount() {
        return signatureCount;
    }

    public void setSignatureCount(Long signatureCount) {
        this.signatureCount = signatureCount;
    }
} 