import React, { useState, useEffect } from 'react';
import axios from 'axios';
import styled, { keyframes, createGlobalStyle } from 'styled-components';

/**
 * Global CSS styles using styled-components for consistent theming
 * and modern visual design across the application
 */
const GlobalStyle = createGlobalStyle`
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

  :root {
    --primary-gradient: linear-gradient(135deg, #6667AB, #9C27B0);
    --accent-gradient: linear-gradient(135deg, #00C9FF, #92FE9D);
    --surface-gradient: linear-gradient(135deg, rgba(255, 255, 255, 0.9), rgba(255, 255, 255, 0.8));
    --card-shadow: 0 10px 30px rgba(0, 0, 0, 0.15), 0 5px 15px rgba(0, 0, 0, 0.1);
    --text-primary: #2D3748;
    --text-secondary: #4A5568;
    --success: #38A169;
    --error: #E53E3E;
    --background-start: #0f0c29;
    --background-mid: #302b63;
    --background-end: #24243e;
  }

  body {
    margin: 0;
    padding: 0;
    font-family: 'Inter', sans-serif;
    background: linear-gradient(135deg, var(--background-start), var(--background-mid), var(--background-end));
    background-size: 400% 400%;
    animation: gradientBG 20s ease infinite;
    min-height: 100vh;
    color: var(--text-primary);
    overflow-x: hidden;
  }
  
  @keyframes gradientBG {
    0% { background-position: 0% 50% }
    50% { background-position: 100% 50% }
    100% { background-position: 0% 50% }
  }

  * {
    box-sizing: border-box;
  }

  ::selection {
    background: rgba(156, 39, 176, 0.3);
  }
`;

/**
 * Utility function to convert base64url encoded strings to ArrayBuffer
 * for WebAuthn API compatibility
 */
function base64urlToArrayBuffer(base64url: string): ArrayBuffer {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * Utility function to convert ArrayBuffer to base64url encoded string
 * for transmission to server
 */
function arrayBufferToBase64url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * CSS-in-JS keyframe animations for various UI effects
 */
const fadeIn = keyframes`
  from { opacity: 0; transform: translateY(20px); }
  to { opacity: 1; transform: translateY(0); }
`;

const pulse = keyframes`
  0% { transform: scale(1); }
  50% { transform: scale(1.05); }
  100% { transform: scale(1); }
`;

const rotate = keyframes`
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
`;

const floatUp = keyframes`
  0% { transform: translateY(20px); opacity: 0; }
  100% { transform: translateY(0); opacity: 1; }
`;

const shimmer = keyframes`
  0% { background-position: -200% 0; }
  100% { background-position: 200% 0; }
`;

const glow = keyframes`
  0%, 100% { box-shadow: 0 0 5px rgba(156, 39, 176, 0.5), 0 0 10px rgba(156, 39, 176, 0.3); }
  50% { box-shadow: 0 0 20px rgba(156, 39, 176, 0.8), 0 0 30px rgba(156, 39, 176, 0.5); }
`;

const ripple = keyframes`
  0% { transform: scale(0.8); opacity: 1; }
  100% { transform: scale(2); opacity: 0; }
`;

const rotate360 = keyframes`
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
`;

const scanEffect = keyframes`
  0% { transform: translateY(-70px); opacity: 0; }
  20% { opacity: 0.8; }
  80% { opacity: 0.8; }
  100% { transform: translateY(70px); opacity: 0; }
`;

const blinkEffect = keyframes`
  0%, 100% { opacity: 0.3; }
  50% { opacity: 1; }
`;

const particleFloat = keyframes`
  0% { transform: translate(0, 0) rotate(0deg); opacity: 0; }
  20% { opacity: 1; }
  80% { opacity: 1; }
  100% { transform: translate(var(--tx), var(--ty)) rotate(var(--r)); opacity: 0; }
`;

const rotateGlow = keyframes`
  0% { transform: translate(-50%, -50%) rotate(0deg); opacity: 0.5; }
  100% { transform: translate(-50%, -50%) rotate(360deg); opacity: 0.8; }
`;

const gentleFloat = keyframes`
  0% { transform: translateY(0px); }
  100% { transform: translateY(-5px); }
`;

/**
 * Styled component for animated particle effects in the security visualization
 */
const Particle = styled.div<{ index: number }>`
  position: absolute;
  width: ${(props: { index: number }) => Math.random() * 3 + 2}px;
  height: ${(props: { index: number }) => Math.random() * 3 + 2}px;
  background: white;
  border-radius: 50%;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  animation: ${particleFloat} 3s ease-out infinite;
  animation-delay: ${(props: { index: number }) => props.index * 0.2}s;
`;

/**
 * Main application container with responsive layout and animated background effects
 */
const AppContainer = styled.div`
  max-width: 900px;
  margin: 0 auto;
  padding: 1.5rem;
  display: flex;
  flex-direction: column;
  align-items: center;
  min-height: 100vh;
  position: relative;
  z-index: 1;
  overflow-x: hidden;
  
  &::before {
    content: '';
    position: absolute;
    top: 10%;
    left: -5%;
    width: 30%;
    height: 20%;
    background: radial-gradient(circle, rgba(156, 39, 176, 0.2) 0%, transparent 70%);
    filter: blur(50px);
    z-index: -1;
    animation: ${floatUp} 3s ease-out infinite alternate;
  }
  
  &::after {
    content: '';
    position: absolute;
    bottom: 15%;
    right: -5%;
    width: 25%;
    height: 30%;
    background: radial-gradient(circle, rgba(0, 201, 255, 0.15) 0%, transparent 70%);
    filter: blur(60px);
    z-index: -1;
    animation: ${floatUp} 4s ease-out infinite alternate 1s;
  }
`;

/**
 * Main content card with glassmorphism effect and shimmer animation
 */
const Card = styled.div`
  background: var(--surface-gradient);
  border-radius: 20px;
  box-shadow: var(--card-shadow);
  backdrop-filter: blur(20px);
  padding: 1.8rem;
  width: 100%;
  max-width: 600px;
  margin-top: 1rem;
  animation: ${floatUp} 0.8s ease-out;
  border: 1px solid rgba(255, 255, 255, 0.2);
  position: relative;
  overflow: hidden;
  
  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
    background-size: 200% 100%;
    animation: ${shimmer} 5s infinite linear;
    z-index: 0;
  }
`;

/**
 * Main application title with gradient text effect and background label
 */
const Title = styled.h1`
  color: white;
  text-align: center;
  margin-bottom: 0.2rem;
  font-size: 2.4rem;
  font-weight: 700;
  text-shadow: 0 2px 10px rgba(156, 39, 176, 0.5);
  background: var(--accent-gradient);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  position: relative;
  z-index: 1;
  letter-spacing: -0.02em;

  &::after {
    content: 'CRYPTOGRAPHY';
    position: absolute;
    left: 50%;
    top: -0.4em;
    transform: translateX(-50%);
    font-size: 0.3em;
    font-weight: 600;
    letter-spacing: 0.2em;
    color: rgba(255, 255, 255, 0.4);
    z-index: -1;
  }
`;

/**
 * Application subtitle with subtle gradient text styling
 */
const Subtitle = styled.h2`
  color: white;
  text-align: center;
  margin-top: 0;
  margin-bottom: 1.5rem;
  font-size: 1.3rem;
  font-weight: 300;
  opacity: 0.9;
  text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
  background: linear-gradient(90deg, #fff, #ccc, #fff);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  letter-spacing: 0.05em;
`;

/**
 * Form input group container with proper spacing and z-index layering
 */
const FormGroup = styled.div`
  margin-bottom: 1.5rem;
  position: relative;
  z-index: 1;
`;

/**
 * Form input label with animated underline effect on focus
 */
const Label = styled.label`
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 500;
  color: var(--text-primary);
  font-size: 0.95rem;
  transition: all 0.3s ease;
  
  &::after {
    content: '';
    display: block;
    width: 0;
    height: 2px;
    background: var(--primary-gradient);
    transition: width 0.3s ease;
  }
`;

/**
 * Text input field with enhanced focus states and smooth transitions
 */
const Input = styled.input`
  width: 100%;
  padding: 1rem 1.2rem;
  border: 1px solid rgba(0, 0, 0, 0.1);
  border-radius: 12px;
  font-size: 1rem;
  transition: all 0.3s ease;
  background: rgba(255, 255, 255, 0.8);
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
  
  &:focus {
    border-color: #9C27B0;
    box-shadow: 0 3px 15px rgba(156, 39, 176, 0.2);
    outline: none;
    background: rgba(255, 255, 255, 0.95);
  }

  &:focus + ${Label}::after {
    width: 50%;
  }
`;

/**
 * Container for action buttons with responsive flex layout and decorative separator
 */
const ButtonContainer = styled.div`
  display: flex;
  gap: 1.2rem;
  margin-top: 2rem;
  flex-wrap: wrap;
  position: relative;
  
  &::before {
    content: '';
    position: absolute;
    top: -20px;
    left: 0;
    right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, rgba(156, 39, 176, 0.3), transparent);
  }
`;

/**
 * Base button component with smooth animations and interactive states
 */
const Button = styled.button`
  padding: 0.9rem 1.5rem;
  border: none;
  border-radius: 12px;
  font-size: 1rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
  position: relative;
  overflow: hidden;
  z-index: 1;
  
  &:hover {
    transform: translateY(-3px) scale(1.02);
    box-shadow: 0 7px 20px rgba(0, 0, 0, 0.1);
  }
  
  &:active {
    transform: translateY(-1px) scale(0.99);
  }
  
  &:disabled {
    opacity: 0.5;
    cursor: not-allowed;
    transform: none;
    box-shadow: none;
  }
  
  &::after {
    content: '';
    position: absolute;
    top: 50%;
    left: 50%;
    width: 5px;
    height: 5px;
    background: rgba(255, 255, 255, 0.4);
    opacity: 0;
    border-radius: 100%;
    transform: scale(1);
    transition: 0.6s;
    z-index: -1;
  }
  
  &:active::after {
    animation: ${ripple} 0.6s ease-out;
  }
`;

const PrimaryButton = styled(Button)`
  background: var(--primary-gradient);
  color: white;
  flex: 1;
  box-shadow: 0 4px 15px rgba(156, 39, 176, 0.3);
  
  &:hover {
    box-shadow: 0 7px 25px rgba(156, 39, 176, 0.5);
    animation: ${glow} 1.5s infinite alternate;
  }
  
  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.1), transparent);
    transition: 0.5s;
    transform: translateX(-100%);
    z-index: -1;
  }
  
  &:hover::before {
    transform: translateX(100%);
  }
`;

const SecondaryButton = styled(Button)`
  background: transparent;
  color: #9C27B0;
  border: 2px solid rgba(156, 39, 176, 0.5);
  flex: 1;
  backdrop-filter: blur(5px);
  
  &:hover {
    background: rgba(156, 39, 176, 0.05);
    border-color: rgba(156, 39, 176, 0.8);
  }
`;

const TertiaryButton = styled(Button)`
  background: transparent;
  color: var(--text-secondary);
  font-size: 0.9rem;
  padding: 0.7rem 1rem;
  font-weight: 500;
  border: 1px solid rgba(0, 0, 0, 0.1);
  
  &:hover {
    background: rgba(0, 0, 0, 0.02);
    color: var(--text-primary);
  }
`;

const Message = styled.div<{ isError?: boolean }>`
  padding: 1.2rem;
  margin-top: 1.8rem;
  border-radius: 12px;
  font-weight: 500;
  animation: ${floatUp} 0.4s ease-out;
  background: ${(props: { isError?: boolean }) => props.isError
    ? 'linear-gradient(135deg, rgba(229, 62, 62, 0.08), rgba(229, 62, 62, 0.03))'
    : 'linear-gradient(135deg, rgba(56, 161, 105, 0.08), rgba(56, 161, 105, 0.03))'};
  color: ${(props: { isError?: boolean }) => props.isError ? 'var(--error)' : 'var(--success)'};
  border-left: 4px solid ${(props: { isError?: boolean }) => props.isError ? 'var(--error)' : 'var(--success)'};
  position: relative;
  
  &::before {
    content: ${(props: { isError?: boolean }) => props.isError ? '"⚠️"' : '"✅"'};
    position: absolute;
    left: -12px;
    top: -12px;
    background: ${(props: { isError?: boolean }) => props.isError ? 'var(--error)' : 'var(--success)'};
    color: white;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 12px;
    box-shadow: 0 3px 10px rgba(0, 0, 0, 0.1);
  }
`;

const DebugContainer = styled.div`
  margin-top: 1.5rem;
  width: 100%;
  overflow: auto;
  max-height: 300px;
  animation: ${floatUp} 0.6s ease-out;
  border-radius: 16px;
  background: rgba(0, 0, 0, 0.03);
  padding: 0.5rem;
  border: 1px solid rgba(0, 0, 0, 0.05);
  position: relative;
`;

const DebugHeader = styled.div`
  color: var(--text-primary);
  margin: 0.5rem;
  font-size: 1rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
  
  h3 {
    margin: 0;
    display: flex;
    align-items: center;
    font-size: 1rem;
    
    &::before {
      content: '🔍';
      margin-right: 0.5rem;
      font-size: 1.2rem;
    }
  }
`;

const CloseButton = styled.button`
  background: transparent;
  border: none;
  color: var(--text-secondary);
  font-size: 1.2rem;
  cursor: pointer;
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
  line-height: 1;
  transition: all 0.2s ease;
  
  &:hover {
    background: rgba(0, 0, 0, 0.05);
    color: var(--text-primary);
  }
`;

const DebugContent = styled.pre`
  background: #f8f9fa;
  padding: 1.2rem;
  border-radius: 12px;
  font-family: 'Fira Code', monospace;
  font-size: 0.85rem;
  line-height: 1.5;
  overflow: auto;
  border: 1px solid rgba(0, 0, 0, 0.05);
  color: #24292e;
`;

const Loader = styled.div`
  display: inline-block;
  width: 18px;
  height: 18px;
  margin-right: 10px;
  border: 2px solid rgba(255, 255, 255, 0.15);
  border-radius: 50%;
  border-top-color: white;
  animation: ${rotate} 0.6s linear infinite;
`;

const Footer = styled.footer`
  text-align: center;
  padding: 1.5rem;
  margin-top: auto;
  color: rgba(255, 255, 255, 0.7);
  font-size: 0.9rem;
  width: 100%;
  position: relative;
  
  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: 25%;
    right: 25%;
    height: 1px;
    background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.3), transparent);
  }
`;

/**
 * Main container for the biometric security visualization with floating animation
 */
const SecurityContainer = styled.div`
  width: 70px;
  height: 70px;
  position: relative;
  margin-top: 1rem;
  margin-bottom: 2rem;
  animation: ${gentleFloat} 3s ease-in-out infinite alternate;
`;

/**
 * Outer circular background with gradient and glow effect
 */
const BioCircle = styled.div`
  position: absolute;
  width: 100%;
  height: 100%;
  border-radius: 50%;
  background: linear-gradient(135deg, rgba(62, 104, 253, 0.8), rgba(156, 39, 176, 0.8));
  box-shadow: 0 0 15px rgba(62, 104, 253, 0.5);
  z-index: 0;
`;

/**
 * Outer ring border for the security visualization
 */
const OuterRing = styled.div`
  width: 100%;
  height: 100%;
  border-radius: 50%;
  border: 2px solid rgba(255, 255, 255, 0.4);
  position: absolute;
  top: 0;
  left: 0;
  display: flex;
  align-items: center;
  justify-content: center;
`;

/**
 * Inner circle containing the security icon with radial gradient background
 */
const InnerCircle = styled.div`
  width: 85%;
  height: 85%;
  background: radial-gradient(circle, rgba(62, 104, 253, 0.9) 0%, rgba(24, 36, 168, 0.9) 100%);
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  position: relative;
  box-shadow: inset 0 0 10px rgba(255, 255, 255, 0.2);
`;

/**
 * Placeholder for scan line animation (currently disabled)
 */
const ScanLine = styled.div`
  display: none;
`;

/**
 * Security lock icon created with CSS pseudo-elements
 */
const FingerScanGraphic = styled.div`
  width: 28px;
  height: 28px;
  position: relative;
  
  /* Lock body */
  &::before {
    content: '';
    position: absolute;
    width: 14px;
    height: 9px;
    background: rgba(255, 255, 255, 0.9);
    border-radius: 2px;
    top: 13px;
    left: 7px;
    box-shadow: 0 0 4px rgba(255, 255, 255, 0.5);
  }
  
  /* Lock shackle */
  &::after {
    content: '';
    position: absolute;
    width: 8px;
    height: 10px;
    border: 2px solid rgba(255, 255, 255, 0.9);
    border-bottom: none;
    border-radius: 4px 4px 0 0;
    top: 4px;
    left: 9px;
    box-shadow: 0 0 4px rgba(255, 255, 255, 0.5);
  }
`;

/**
 * Small circular accent element within the security icon
 */
const FingerprintLines = styled.div`
  position: absolute;
  width: 4px;
  height: 4px;
  background: rgba(255, 255, 255, 0.8);
  border-radius: 50%;
  top: 17px;
  left: 14px;
  box-shadow: 0 0 3px rgba(255, 255, 255, 0.6);
`;

/**
 * Placeholder for fingerprint arc visualization (currently disabled)
 */
const FingerprintArc = styled.div`
  display: none;
`;

/**
 * Animated security indicator dots with blinking effect
 */
const SecurityDots = styled.div`
  position: absolute;
  width: 100%;
  height: 100%;
  top: 0;
  left: 0;
  
  &::before, &::after {
    content: '';
    position: absolute;
    width: 3px;
    height: 3px;
    background: rgba(255, 255, 255, 0.7);
    border-radius: 50%;
    animation: ${blinkEffect} 2s infinite;
  }
  
  &::before {
    top: 20%;
    left: 15%;
    animation-delay: 0.5s;
  }
  
  &::after {
    top: 25%;
    right: 15%;
    animation-delay: 1s;
  }
`;

/**
 * Decorative rotating element around the security visualization (currently unused)
 */
const RotatingElement = styled.div`
  position: absolute;
  width: 170px;
  height: 170px;
  border: 1px dashed rgba(255, 255, 255, 0.2);
  border-radius: 50%;
  top: -15px;
  left: -15px;
  animation: ${rotate360} 30s linear infinite reverse;
  
  &::before {
    content: '';
    position: absolute;
    width: 10px;
    height: 10px;
    background: rgba(255, 255, 255, 0.8);
    border-radius: 50%;
    top: 80px;
    left: 0;
  }
  
  &::after {
    content: '';
    position: absolute;
    width: 6px;
    height: 6px;
    background: rgba(62, 104, 253, 0.8);
    border-radius: 50%;
    bottom: 80px;
    right: 0;
  }
`;

/**
 * TypeScript interface for security warning items received from the backend
 */
type WarningItem = {
    id: string;
    timestamp: string;
    ipAddress: string;
    country: string;
    triggeredRules: string;
};
const WarningInfo = styled.div`
  flex: 1;
  min-width: 0;
`;

const WarningTime = styled.div`
  font-weight: 600;
  margin-bottom: 0.25rem;
`;

const WarningDetails = styled.div`
  font-size: .85rem;
  color: #ffffff;
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
`;


const WarningBanner = styled.div`
  background: linear-gradient(135deg, rgba(62, 104, 253, 0.8), rgba(156, 39, 176, 0.8));
  color: #ffffff;
  border-left: 6px solid #7107a8;
  padding: 1rem 1.25rem;
  margin-top: 1.25rem;
  border-radius: 12px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
  animation: ${floatUp} 0.6s ease-out;
  max-height: none; /* ✅ Let it expand as needed to avoid scroll clipping */
  overflow: visible; /* ✅ Ensure buttons are not clipped */
  position: relative;
  z-index: 1;
`;

const WarningItemRow = styled.div`
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  padding: 0.75rem 0;
  border-top: 1px solid rgba(0, 0, 0, 0.05);
  gap: 1rem;
  position: relative;
  z-index: 2;

  &:first-child {
    border-top: none;
  }
`;

const WarningButtons = styled.div`
  display: flex;
  gap: 0.5rem;
  flex-shrink: 0;
  position: relative;
  z-index: 3; /* ✅ Force buttons to top layer */

  button {
    font-size: 0.8rem;
    padding: 0.4rem 0.8rem;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.2s ease;
    white-space: nowrap;

    &:hover {
      transform: translateY(-1px);
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }

    &:active {
      transform: translateY(0);
    }
  }
`;

const ConfirmButton = styled.button`
  background: #38A169;
  color: #fff;

  &:hover {
    background: #2F855A;
  }
`;

const DenyButton = styled.button`
  background: #E53E3E;
  color: #fff;

  &:hover {
    background: #C53030;
  }
`;

/**
 * Main React component for the passwordless authentication application
 */
const App: React.FC = () => {
    const [username, setUsername] = useState('');
    const [displayName, setDisplayName] = useState('');
    const [message, setMessage] = useState('');
    const [error, setError] = useState('');
    const [debugInfo, setDebugInfo] = useState<any>(null);
    const [isLoading, setIsLoading] = useState(false);
    const [warnings, setWarnings] = useState<WarningItem[]>([]);
    const [showWarnings, setShowWarnings] = useState<boolean>(false);

    // Array for particle animation effects
    const [particles] = useState(Array.from({ length: 6 }, (_, i) => i));

    // Set document title on component mount
    useEffect(() => {
        document.title = "Cryptography - Group 07 | Passwordless Auth";
    }, []);

    /**
     * Toggles display of WebAuthn debug information including browser support details
     */
    const handleDebugInfo = () => {
        // If debug info is already showing, close it instead
        if (debugInfo) {
            setDebugInfo(null);
            setMessage('');
            return;
        }

        try {
            const debugData = {
                isWebAuthnSupported: !!window.PublicKeyCredential,
                isSecureContext: window.isSecureContext,
                browserInfo: navigator.userAgent,
                availableFunctions: {
                    credentials: !!navigator.credentials,
                    create: !!(navigator.credentials && navigator.credentials.create),
                    get: !!(navigator.credentials && navigator.credentials.get),
                }
            };

            // Test platform authenticator availability if API is supported
            if (typeof PublicKeyCredential !== 'undefined' &&
                typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
                PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
                    .then((isAvailable) => {
                        const updatedDebugData = {
                            ...debugData,
                            isPlatformAuthenticatorAvailable: isAvailable
                        };
                        setDebugInfo(updatedDebugData);
                        setMessage('WebAuthn debug information collected.');
                    });
            } else {
                setDebugInfo(debugData);
                setMessage('WebAuthn debug information collected (limited).');
            }
        } catch (err) {
            console.error('Error checking WebAuthn support:', err);
            setError(`Error checking WebAuthn support: ${err}`);
        }
    };

    /**
     * Fetches previous security warnings for the authenticated user
     */
    const fetchWarnings = async (user: string) => {
        try {
            const res = await axios.get<WarningItem[]>(
                `/api/warnings/previous/${encodeURIComponent(user)}`
            );
            if (res.data.length > 0) {
                setWarnings(res.data);
                setShowWarnings(true);
            } else {
                setWarnings([]);
                setShowWarnings(false);
            }
        } catch (err) {
            console.error('Warning fetch failed', err);
        }
    };

    /**
     * Closes the debug information panel
     */
    const closeDebugInfo = () => {
        setDebugInfo(null);
        setMessage('');
    };

    /**
     * Sends user feedback about security warnings to improve the detection system
     */
    const sendFeedback = async (warningId: string, isLegit: boolean) => {
        try {
            const response = await axios.post(`/api/feedback/${isLegit ? 'true-positive' : 'true-negative'}/${warningId}`);

            if (response.data.status === 'success' || response.data.status === 'warning') {
                // Update UI optimistically after successful feedback
                setWarnings(prev => prev.filter(w => w.id !== warningId));
                if (warnings.length === 1) setShowWarnings(false);
                setMessage(response.data.message);
            } else {
                setError(response.data.message || 'Failed to record feedback');
            }
        } catch (err) {
            console.error('Feedback failed:', err);
            setError('Failed to record feedback. Please try again.');
        }
    };

    /**
     * Handles WebAuthn biometric registration process
     * Implements the complete WebAuthn registration flow with fallback options
     */
    const handleRegister = async () => {
        if (!username || !displayName) {
            setError('Username and display name are required');
            return;
        }

        try {
            setError('');
            setMessage('');
            setIsLoading(true);
            setDebugInfo(null);
            setMessage('Starting registration...');

            // Step 1: Request registration options from the server
            console.log('Requesting registration options...');
            const optionsResponse = await axios.post(
                `/api/webauthn/register/options?username=${encodeURIComponent(username)}&displayName=${encodeURIComponent(displayName)}`
            );

            let publicKeyCredentialCreationOptions = optionsResponse.data;
            console.log('Registration options received:', publicKeyCredentialCreationOptions);

            // Remove extensions to prevent compatibility issues
            delete publicKeyCredentialCreationOptions.extensions;

            setDebugInfo(publicKeyCredentialCreationOptions);

            // Convert base64url strings to ArrayBuffers for WebAuthn API compatibility
            publicKeyCredentialCreationOptions.challenge = base64urlToArrayBuffer(
                publicKeyCredentialCreationOptions.challenge
            );
            publicKeyCredentialCreationOptions.user.id = base64urlToArrayBuffer(
                publicKeyCredentialCreationOptions.user.id
            );

            // Convert excludeCredentials if present
            if (publicKeyCredentialCreationOptions.excludeCredentials) {
                publicKeyCredentialCreationOptions.excludeCredentials =
                    publicKeyCredentialCreationOptions.excludeCredentials.map((credential: any) => ({
                        ...credential,
                        id: base64urlToArrayBuffer(credential.id)
                    }));
            }

            console.log('Prepared options for WebAuthn API:', publicKeyCredentialCreationOptions);

            if (!window.PublicKeyCredential) {
                throw new Error('WebAuthn is not supported in this browser');
            }

            let credential;

            try {
                // Step 2: Attempt credential creation with full server options
                console.log('Creating credentials...');
                credential = await navigator.credentials.create({
                    publicKey: publicKeyCredentialCreationOptions
                }) as PublicKeyCredential;
            } catch (credentialError) {
                console.error('Failed with standard options, using fallback method', credentialError);

                const params = [{
                    type: 'public-key' as const,
                    alg: -7 // ES256 algorithm
                }];

                // Fallback: Use simplified options for better compatibility
                const simplifiedOptions = {
                    publicKey: {
                        rp: publicKeyCredentialCreationOptions.rp,
                        user: publicKeyCredentialCreationOptions.user,
                        challenge: publicKeyCredentialCreationOptions.challenge,
                        pubKeyCredParams: params,
                        timeout: 60000,
                        attestation: 'none' as AttestationConveyancePreference
                    }
                };

                console.log('Trying simplified options:', simplifiedOptions);
                credential = await navigator.credentials.create(simplifiedOptions) as PublicKeyCredential;
            }

            console.log('Credential created:', credential);

            // Step 3: Prepare credential response data for server transmission
            const attestationResponse = credential.response as AuthenticatorAttestationResponse;

            const registrationResponse = {
                id: credential.id,
                rawId: arrayBufferToBase64url(credential.rawId),
                response: {
                    attestationObject: arrayBufferToBase64url(attestationResponse.attestationObject),
                    clientDataJSON: arrayBufferToBase64url(attestationResponse.clientDataJSON)
                },
                type: credential.type,
                clientExtensionResults: credential.getClientExtensionResults()
            };

            console.log('Registration response prepared:', registrationResponse);

            // Step 4: Send credential to server for verification and storage
            console.log('Sending registration response to server...');
            const finalResponse = await axios.post(
                `/api/webauthn/register?username=${encodeURIComponent(username)}`,
                JSON.stringify(registrationResponse),
                {
                    headers: { 'Content-Type': 'application/json' }
                }
            );

            console.log('Registration completed successfully:', finalResponse);
            setMessage('Registration successful! You can now authenticate.');
            setIsLoading(false);
        } catch (err: any) {
            console.error('Registration error:', err);
            setDebugInfo(err.response?.data || err.message || err);
            setError(`Registration failed: ${err.response?.data?.message || err.message || 'Unknown error'}`);
            setIsLoading(false);
        }
    };

    /**
     * Handles WebAuthn biometric authentication process
     * Authenticates users using their registered biometric credentials
     */
    const handleAuthenticate = async () => {
        if (!username) {
            setError('Username is required');
            return;
        }

        try {
            setError('');
            setMessage('');
            setIsLoading(true);
            setDebugInfo(null);
            setMessage('Starting authentication...');

            // Step 1: Request authentication options from the server
            console.log('Requesting authentication options...');
            const optionsResponse = await axios.post(
                `/api/webauthn/authenticate/options?username=${encodeURIComponent(username)}`
            );

            let publicKeyCredentialRequestOptions = optionsResponse.data;
            console.log('Authentication options received:', publicKeyCredentialRequestOptions);

            // Remove extensions to prevent compatibility issues
            delete publicKeyCredentialRequestOptions.extensions;

            setDebugInfo(publicKeyCredentialRequestOptions);

            // Convert base64url challenge to ArrayBuffer for WebAuthn API
            publicKeyCredentialRequestOptions.challenge = base64urlToArrayBuffer(
                publicKeyCredentialRequestOptions.challenge
            );

            // Convert allowCredentials identifiers if present
            if (publicKeyCredentialRequestOptions.allowCredentials &&
                publicKeyCredentialRequestOptions.allowCredentials.length > 0) {
                publicKeyCredentialRequestOptions.allowCredentials =
                    publicKeyCredentialRequestOptions.allowCredentials.map(
                        (credential: any) => ({
                            ...credential,
                            id: base64urlToArrayBuffer(credential.id)
                        })
                    );
            }

            console.log('Prepared options for WebAuthn API:', publicKeyCredentialRequestOptions);

            if (!window.PublicKeyCredential) {
                throw new Error('WebAuthn is not supported in this browser');
            }

            let credential;

            try {
                // Step 2: Request credential from authenticator device
                console.log('Getting credentials...');
                credential = await navigator.credentials.get({
                    publicKey: publicKeyCredentialRequestOptions
                }) as PublicKeyCredential;
            } catch (credentialError) {
                console.error('Failed with standard options, using fallback method', credentialError);

                // Fallback: Use minimal options for better compatibility
                const simplifiedOptions = {
                    publicKey: {
                        challenge: publicKeyCredentialRequestOptions.challenge,
                        rpId: publicKeyCredentialRequestOptions.rpId || 'localhost',
                        timeout: 60000,
                        userVerification: 'preferred' as UserVerificationRequirement
                    }
                };

                console.log('Trying simplified options:', simplifiedOptions);
                credential = await navigator.credentials.get(simplifiedOptions) as PublicKeyCredential;
            }

            console.log('Credential received:', credential);

            // Step 3: Prepare authentication response data for server
            const assertionResponse = credential.response as AuthenticatorAssertionResponse;

            const authenticationResponse = {
                id: credential.id,
                rawId: arrayBufferToBase64url(credential.rawId),
                response: {
                    authenticatorData: arrayBufferToBase64url(assertionResponse.authenticatorData),
                    clientDataJSON: arrayBufferToBase64url(assertionResponse.clientDataJSON),
                    signature: arrayBufferToBase64url(assertionResponse.signature),
                    userHandle: assertionResponse.userHandle
                        ? arrayBufferToBase64url(assertionResponse.userHandle)
                        : null
                },
                type: credential.type,
                clientExtensionResults: credential.getClientExtensionResults()
            };

            console.log('Authentication response prepared:', authenticationResponse);

            // Step 4: Send authentication data to server for verification
            console.log('Sending authentication response to server...');
            const finalResponse = await axios.post(
                `/api/webauthn/authenticate?username=${encodeURIComponent(username)}`,
                JSON.stringify(authenticationResponse),
                {
                    headers: { 'Content-Type': 'application/json' }
                }
            );

            console.log('Authentication completed successfully:', finalResponse);
            setMessage('Authentication successful!');
            await fetchWarnings(username);
            setIsLoading(false);
        } catch (err: any) {
            console.error('Authentication error:', err);
            setDebugInfo(err.response?.data || err.message || err);
            setError(`Authentication failed: ${err.response?.data?.message || err.message || 'Unknown error'}`);
            setIsLoading(false);
        }
    };

    return (
        <>
            <GlobalStyle />
            <AppContainer>
                <SecurityContainer>
                    <BioCircle />
                    <OuterRing>
                        <InnerCircle>
                            <ScanLine />
                            <FingerScanGraphic>
                                <FingerprintLines />
                            </FingerScanGraphic>
                            {particles.map((index) => (
                                <Particle key={index} index={index} style={{
                                    '--tx': `${(Math.random() * 2 - 1) * 50}px`,
                                    '--ty': `${(Math.random() * 2 - 1) * 50}px`,
                                    '--r': `${Math.random() * 360}deg`
                                } as React.CSSProperties} />
                            ))}
                            <SecurityDots />
                        </InnerCircle>
                    </OuterRing>
                </SecurityContainer>
                <Title>Cryptography - Group 07</Title>
                <Subtitle>Passwordless Authentication Prototype</Subtitle>

                <Card>
                    <FormGroup>
                        <Label htmlFor="username">Username:</Label>
                        <Input
                            id="username"
                            type="text"
                            value={username}
                            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setUsername(e.target.value)}
                            placeholder="Enter your username"
                        />
                    </FormGroup>

                    <FormGroup>
                        <Label htmlFor="displayName">Display Name:</Label>
                        <Input
                            id="displayName"
                            type="text"
                            value={displayName}
                            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setDisplayName(e.target.value)}
                            placeholder="Enter your display name"
                        />
                    </FormGroup>

                    <ButtonContainer>
                        <PrimaryButton
                            onClick={handleRegister}
                            disabled={isLoading || !username || !displayName}
                        >
                            {isLoading && <Loader />}
                            Register with Biometrics
                        </PrimaryButton>
                        <SecondaryButton
                            onClick={handleAuthenticate}
                            disabled={isLoading || !username}
                        >
                            {isLoading && <Loader />}
                            Authenticate
                        </SecondaryButton>
                    </ButtonContainer>

                    <div style={{ textAlign: 'center', marginTop: '1.5rem' }}>
                        <TertiaryButton
                            onClick={handleDebugInfo}
                            disabled={isLoading}
                        >
                            {debugInfo ? 'Hide WebAuthn Info' : 'Check WebAuthn Support'}
                        </TertiaryButton>
                    </div>

                    {message && <Message>{message}</Message>}
                    {error && <Message isError>{error}</Message>}

                    {debugInfo && (
                        <DebugContainer>
                            <DebugHeader>
                                <h3>Debug Information</h3>
                                <CloseButton onClick={closeDebugInfo}>✕</CloseButton>
                            </DebugHeader>
                            <DebugContent>
                                {JSON.stringify(debugInfo, null, 2)}
                            </DebugContent>
                        </DebugContainer>
                    )}

                    {showWarnings && warnings.length > 0 && (
                        <WarningBanner>
                            <strong>We noticed {warnings.length} suspicious login{warnings.length>1?'s':''} from your previous session:</strong>
                            {warnings.map(w => {
                                const rules = JSON.parse(w.triggeredRules || '[]');
                                return (
                                    <WarningItemRow key={w.id}>
                                        <WarningInfo>
                                            <WarningTime>
                                                {new Date(w.timestamp).toLocaleString()}
                                            </WarningTime>
                                            <WarningDetails>
                                                <div>IP Address: {w.ipAddress}</div>
                                                <div>Triggered Rules: {Array.isArray(rules) ? rules.join(', ') : 'No rules triggered'}</div>
                                            </WarningDetails>
                                        </WarningInfo>
                                        <WarningButtons>
                                            <ConfirmButton
                                                onClick={() => sendFeedback(w.id, true)}
                                            >
                                                Yes, it was me
                                            </ConfirmButton>
                                            <DenyButton
                                                onClick={() => sendFeedback(w.id, false)}
                                            >
                                                No, wasn't me
                                            </DenyButton>
                                        </WarningButtons>
                                    </WarningItemRow>
                                );
                            })}
                        </WarningBanner>
                    )}
                </Card>

                <Footer>
                    © {new Date().getFullYear()} Passwordless Authentication Prototype | Cryptography - Group 07
                </Footer>
            </AppContainer>
        </>
    );
};

export default App;