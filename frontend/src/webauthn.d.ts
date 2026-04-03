/**
 * TypeScript declarations for WebAuthn API interfaces.
 * These types provide strong typing for biometric authentication operations.
 * 
 * Based on the W3C Web Authentication API specification:
 * https://www.w3.org/TR/webauthn-2/
 */

/** Options for creating new WebAuthn credentials during registration */
interface PublicKeyCredentialCreationOptions {
  challenge: BufferSource;
  rp: PublicKeyCredentialRpEntity;
  user: PublicKeyCredentialUserEntity;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  timeout?: number;
  excludeCredentials?: PublicKeyCredentialDescriptor[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  attestation?: string;
  extensions?: any;
}

/** Relying Party (application) identification information */
interface PublicKeyCredentialRpEntity {
  id?: string;
  name: string;
}

/** User identification information for credential creation */
interface PublicKeyCredentialUserEntity {
  id: BufferSource;
  name: string;
  displayName: string;
}

/** Cryptographic algorithm parameters for credential creation */
interface PublicKeyCredentialParameters {
  type: string;
  alg: number;
}

/** Descriptor for existing credentials to exclude or allow */
interface PublicKeyCredentialDescriptor {
  type: string;
  id: BufferSource;
  transports?: string[];
}

/** Criteria for selecting authenticator devices */
interface AuthenticatorSelectionCriteria {
  authenticatorAttachment?: string;
  requireResidentKey?: boolean;
  residentKey?: string;
  userVerification?: string;
}

/** Options for requesting credential assertions during authentication */
interface PublicKeyCredentialRequestOptions {
  challenge: BufferSource;
  timeout?: number;
  rpId?: string;
  allowCredentials?: PublicKeyCredentialDescriptor[];
  userVerification?: string;
  extensions?: any;
}

/** WebAuthn credential returned by the authenticator */
interface PublicKeyCredential extends Credential {
  rawId: ArrayBuffer;
  response: AuthenticatorResponse;
  getClientExtensionResults(): any;
}

/** Base authenticator response interface */
interface AuthenticatorResponse {
  clientDataJSON: ArrayBuffer;
}

/** Response from credential creation (registration) */
interface AuthenticatorAttestationResponse extends AuthenticatorResponse {
  attestationObject: ArrayBuffer;
}

/** Response from credential assertion (authentication) */
interface AuthenticatorAssertionResponse extends AuthenticatorResponse {
  authenticatorData: ArrayBuffer;
  signature: ArrayBuffer;
  userHandle: ArrayBuffer | null;
} 