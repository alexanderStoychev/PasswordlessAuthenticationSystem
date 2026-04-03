## Passwordless Authentication System

A modern passwordless authentication system using WebAuthn/FIDO2 standards for secure, passwordless login. This project demonstrates the implementation of FIDO2/WebAuthn standards for biometric and security key authentication, alongside advanced contextual analysis and experimental research on intrusion detection and usability.

## Features

- **WebAuthn/FIDO2 Authentication**: Secure passwordless authentication using public key cryptography
- **Biometric Authentication Support**: Leverage fingerprint, facial recognition, or other biometric methods
- **Security Key Support**: Compatible with FIDO2 security keys (Yubikey, etc.)
- **Modern Responsive UI**: Clean, animated interface with styled-components
- **Cross-Browser Compatibility**: Works across major modern browsers
- **Debug Information**: Built-in debugging tools to check WebAuthn support
- **Hot Reloading**: Frontend development server has hot reloading enabled for rapid development
- **Contextual Analysis**: Advanced login attempt analysis based on IP, user agent, timing, and behavior patterns
- **Experimental Research**: Includes simulations for credential stuffing, account hijacking, and usability impact analysis

## Prerequisites

- Java 17 or later
- Node.js 16 or later
- Maven
- npm or yarn
- A compatible browser with WebAuthn support (Chrome, Firefox, Edge, Safari)
- Secure context (HTTPS or localhost)

## Tech Stack

- **Backend**: Java Spring Boot with Yubico WebAuthn Server library
- **Frontend**: React with TypeScript and styled-components
- **Authentication**: WebAuthn/FIDO2 standards
- **API Communication**: Axios for HTTP requests
- **Database**: H2 in-memory database (for development)
- **Analysis & Experiments**: Custom rule-based contextual analysis and feedback learning system

## Project Structure

```
.
├── src/                    # Backend source code
│   └── main/
│       ├── java/
│       │   └── com/passwordless/auth/
│       │       ├── config/            # WebAuthn configuration
│       │       ├── controller/        # REST endpoints for auth and experiments
│       │       ├── model/             # Data models for users and events
│       │       ├── repository/        # Database access layers
│       │       └── service/           # Business logic for auth and analysis
│       └── resources/                 # Application resources
└── frontend/               # Frontend source code
    ├── src/
    │   ├── App.tsx         # Main application component
    │   └── index.tsx       # Entry point
    └── public/             # Static assets
```

## Running the Application

### Backend

1. Navigate to the project root directory:
```bash
cd passwordless-auth
```

2. Build and run the Spring Boot application:
```bash
./mvnw spring-boot:run
```

The backend will be available at http://localhost:8080

### Frontend

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm start
```

The frontend will be available at http://localhost:3000 or http://localhost:3001

## Usage Guide

1. **Registration**:
   - Enter a username and display name
   - Click "Register with Biometrics"
   - Follow your browser's prompts to register your biometric or security key

2. **Authentication**:
   - Enter your registered username
   - Click "Authenticate"
   - Follow your browser's prompts to authenticate with your biometric or security key

3. **Debug Information**:
   - Click "Check WebAuthn Support" to view browser compatibility and WebAuthn support details
   - Click the button again to hide the debug information

4. **Experimental Features**:
   - Access experimental endpoints at `/api/experiments/*` to simulate attacks like credential stuffing or hijacking
   - Review contextual analysis results and system learning through feedback mechanisms

## WebAuthn Implementation Details

The WebAuthn implementation uses the following flow:

1. **Registration Process**:
   - Server generates registration options (challenge, relying party info)
   - Client receives options and creates credentials via WebAuthn API
   - Server verifies the attestation and stores credential information

2. **Authentication Process**:
   - Server generates authentication options (challenge, allowed credentials)
   - Client receives options and provides an assertion via WebAuthn API
   - Server verifies the assertion against stored credentials

## Contextual Analysis & Experiments

This project includes advanced features for analyzing login attempts and conducting security experiments:

- **Contextual Analysis**: Evaluates login attempts based on rules like rapid logins, new IPs, unusual times, and recent failures
- **Feedback Learning**: Adjusts rule weights based on feedback to improve detection accuracy
- **Experiments**: Simulates attack scenarios (e.g., credential stuffing, hijack after failures) and measures false positives for usability impact
- **Usability Metrics**: Calculates theoretical usability scores to balance security and user experience

## Development

- Backend API endpoints are available at `/api/webauthn/*` for authentication and `/api/experiments/*` for research simulations
- H2 Console is available at http://localhost:8080/h2-console (if enabled)

## Testing

### Backend Tests
```bash
./mvnw test
```

### Frontend Tests
```bash
cd frontend
npm test
```

## Troubleshooting

- **Browser Compatibility**: Ensure you're using a modern browser with WebAuthn support
- **Secure Context**: WebAuthn requires a secure context (HTTPS or localhost)
- **Debug Information**: Use the "Check WebAuthn Support" button to diagnose issues
- **Device Compatibility**: Some devices may not support certain WebAuthn features
- **Java Version**: Ensure Java 17 is used due to compatibility with Spring Boot 3.2.3

## Security Considerations

- WebAuthn provides phishing-resistant authentication
- Credentials are stored securely using WebAuthn standards
- Public key cryptography ensures passwords never leave the device
- CSRF protection is disabled for development
- CORS is configured to allow local development

## Future Enhancements

- Multi-device credential management
- Account recovery options
- Transaction confirmation
- Enhanced UX for credential management
- Real user studies to validate usability metrics
- Integration of additional contextual rules for analysis
