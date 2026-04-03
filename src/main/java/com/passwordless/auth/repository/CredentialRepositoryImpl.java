package com.passwordless.auth.repository;

import com.passwordless.auth.model.Credential;
import com.passwordless.auth.model.User;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Repository
public class CredentialRepositoryImpl implements CredentialRepository {

    @Autowired
    private JpaCredentialRepository credentialRepository;

    @Autowired
    private UserRepository userRepository;

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        return userRepository.findByUsername(username)
                .map(user -> {
                    List<Credential> credentials = credentialRepository.findByUser(user);
                    System.out.println("Found " + credentials.size() + " credentials for user: " + username);
                    
                    return credentials.stream()
                        .map(credential -> {
                            try {
                                // Properly decode the Base64 string to get the raw bytes
                                ByteArray credId = ByteArray.fromBase64(credential.getCredentialId());
                                System.out.println("Credential ID for auth options: " + credId);
                                return PublicKeyCredentialDescriptor.builder()
                                    .id(credId)
                                    .build();
                            } catch (Exception e) {
                                System.err.println("Error decoding credential ID: " + e.getMessage());
                                return null;
                            }
                        })
                        .filter(cred -> cred != null)
                        .collect(Collectors.toSet());
                })
                .orElse(new HashSet<>());
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return userRepository.findByUsername(username)
                .map(user -> new ByteArray(user.getHandle().getBytes()));
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        return userRepository.findAll().stream()
                .filter(user -> userHandle.equals(new ByteArray(user.getHandle().getBytes())))
                .findFirst()
                .map(User::getUsername);
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        // Log the incoming credential ID for debugging
        System.out.println("Looking up credential ID: " + credentialId);
        System.out.println("Credential ID in Base64: " + credentialId.getBase64());
        
        // Try to find the credential by its base64 representation
        Optional<Credential> credential = credentialRepository.findByCredentialId(credentialId.getBase64());
        
        if (credential.isPresent()) {
            System.out.println("Found credential with ID: " + credential.get().getCredentialId());
        } else {
            System.out.println("No credential found with ID: " + credentialId.getBase64());
        }
        
        return credential
                .filter(cred -> userHandle.equals(
                        new ByteArray(cred.getUser().getHandle().getBytes()))
                )
                .map(cred -> RegisteredCredential.builder()
                        .credentialId(ByteArray.fromBase64(cred.getCredentialId()))
                        .userHandle(new ByteArray(cred.getUser().getHandle().getBytes()))
                        .publicKeyCose(ByteArray.fromBase64(cred.getPublicKeyCose()))
                        .signatureCount(cred.getSignatureCount())
                        .build());
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        System.out.println("Looking up all credentials with ID: " + credentialId.getBase64());
        
        return credentialRepository.findByCredentialId(credentialId.getBase64())
                .map(credential -> RegisteredCredential.builder()
                        .credentialId(ByteArray.fromBase64(credential.getCredentialId()))
                        .userHandle(new ByteArray(credential.getUser().getHandle().getBytes()))
                        .publicKeyCose(ByteArray.fromBase64(credential.getPublicKeyCose()))
                        .signatureCount(credential.getSignatureCount())
                        .build())
                .map(Set::of)
                .orElse(new HashSet<>());
    }
} 