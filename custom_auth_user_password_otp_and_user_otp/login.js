'use client';
import React, { useState, useEffect, useRef } from 'react';
import { CognitoIdentityProviderClient, InitiateAuthCommand, RespondToAuthChallengeCommand } from '@aws-sdk/client-cognito-identity-provider';
import { LambdaClient, InvokeCommand } from '@aws-sdk/client-lambda';
import { EyeIcon, EyeSlashIcon } from '@heroicons/react/24/outline';

// Initialize Cognito and Lambda clients
const cognitoClient = new CognitoIdentityProviderClient({ region: process.env.NEXT_PUBLIC_AWS_COGNITO_REGION });
const lambdaClient = new LambdaClient({
  region: process.env.NEXT_PUBLIC_AWS_COGNITO_REGION,
  credentials: {
    accessKeyId: process.env.NEXT_PUBLIC_AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.NEXT_PUBLIC_AWS_SECRET_ACCESS_KEY,
  },
});

// Helper function to map failure reasons to user-friendly messages
const getErrorMessage = (failureReason, defaultMessage) => {
  switch (failureReason) {
    case 'INVALID_PASSWORD':
      return 'Incorrect username or password.';
    case 'MAX_OTP_RESEND_ATTEMPTS_EXCEEDED':
      return 'Maximum OTP resend attempts exceeded. Please restart the login process.';
    case 'INVALID_CHALLENGE_STATE':
      return 'Invalid authentication state. Please try logging in again.';
    case 'UNKNOWN_ERROR':
      return 'An unexpected error occurred. Please try again.';
    case 'RESEND_RATE_LIMIT':
      return 'Please wait before requesting a new OTP.';
    case 'NO_CONTACT_METHOD':
      return 'No contact method (phone or email) is available for OTP delivery.';
    case 'INVALID_PHONE_NUMBER':
      return 'Invalid phone number provided. Please update your account details.';
    case 'SERVER_ERROR':
      return 'Server error during authentication. Please try again later.';
    case 'MISSING_USERNAME':
      return 'Username is missing. Please provide a valid username.';
    case 'VERIFICATION_ERROR':
      return 'Error verifying your credentials. Please try again.';
    case 'Invalid or expired OTP':
      return 'The OTP you entered is invalid or has expired.';
    case 'Password does not meet requirements':
      return 'The new password does not meet the requirements.';
    case 'User not found':
      return 'User not found. Please check your username.';
    case 'INVALID_AUTH_FLOW':
      return 'Invalid authentication flow selected. Please try again.';
    default:
      return defaultMessage || 'Authentication failed. Please try again.';
  }
};

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [otp, setOtp] = useState(['', '', '', '']);
  const [authFlow, setAuthFlow] = useState('PASSWORD_OTP'); // Default to PASSWORD_OTP
  const [stage, setStage] = useState('selectFlow'); // 'selectFlow', 'password', 'otp', 'resetPassword', 'success'
  const [error, setError] = useState('');
  const [tokens, setTokens] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [session, setSession] = useState(null);
  const [resendDisabled, setResendDisabled] = useState(true);
  const [resendTimer, setResendTimer] = useState(10);
  const [showPassword, setShowPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const inputRefs = useRef([]);

  useEffect(() => {
    if ((stage === 'otp' || stage === 'resetPassword') && resendDisabled) {
      const timer = setInterval(() => {
        setResendTimer((prev) => {
          if (prev <= 1) {
            setResendDisabled(false);
            clearInterval(timer);
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
      return () => clearInterval(timer);
    }
  }, [stage, resendDisabled]);

  const handleFlowSelectionSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setTokens(null);
    setIsLoading(true);
    const clientId = process.env.NEXT_PUBLIC_AWS_COGNITO_APP_CLIENT_ID;

    try {
      // Initiate authentication
      const initiateResponse = await cognitoClient.send(
        new InitiateAuthCommand({
          AuthFlow: 'CUSTOM_AUTH',
          ClientId: clientId,
          AuthParameters: { USERNAME: username },
        })
      );
      console.log("initiateResponse: ",initiateResponse);
      console.log(initiateResponse.Session)
      const challenge = initiateResponse.ChallengeParameters?.challenge;
      if (initiateResponse.ChallengeName !== 'CUSTOM_CHALLENGE' || challenge !== 'SELECT_AUTH_FLOW') {
        throw new Error(
          initiateResponse.ChallengeParameters?.failureReason || `Expected SELECT_AUTH_FLOW but got ${challenge || 'none'}`
        );
      }

      // Respond to SELECT_AUTH_FLOW challenge
      const challengeResponse = await cognitoClient.send(
        new RespondToAuthChallengeCommand({
          ChallengeName: 'CUSTOM_CHALLENGE',
          ClientId: clientId,
          ChallengeResponses: {
            USERNAME: username,
            ANSWER: authFlow,
          },
          Session: initiateResponse.Session,
        })
      );
      console.log("challengeResponse: ",challengeResponse);

      const nextChallenge = challengeResponse.ChallengeParameters?.challenge;
      if (challengeResponse.ChallengeName === 'CUSTOM_CHALLENGE') {
        if (authFlow === 'PASSWORD_OTP' && nextChallenge === 'PASSWORD_CHALLENGE') {
          setStage('password');
          setSession(challengeResponse.Session);
        } else if (authFlow === 'OTP_ONLY' && nextChallenge === 'OTP_CHALLENGE') {
          setStage('otp');
          setSession(challengeResponse.Session);
          setResendDisabled(true);
          setResendTimer(10);
        } else {
          throw new Error(
            challengeResponse.ChallengeParameters?.failureReason || `Expected ${authFlow === 'PASSWORD_OTP' ? 'PASSWORD_CHALLENGE' : 'OTP_CHALLENGE'} but got ${nextChallenge || 'none'}`
          );
        }
      } else if (challengeResponse.AuthenticationResult) {
        setTokens(challengeResponse.AuthenticationResult);
        setStage('success');
      } else {
        throw new Error(
          challengeResponse.ChallengeParameters?.failureReason || `Unexpected response after SELECT_AUTH_FLOW`
        );
      }
    } catch (err) {
      setError(getErrorMessage(err.message || err.ChallengeParameters?.failureReason, 'Failed to select authentication flow.'));
    } finally {
      setIsLoading(false);
    }
  };

  const handlePasswordSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);
    const clientId = process.env.NEXT_PUBLIC_AWS_COGNITO_APP_CLIENT_ID;

    try {
      const challengeResponse = await cognitoClient.send(
        new RespondToAuthChallengeCommand({
          ChallengeName: 'CUSTOM_CHALLENGE',
          ClientId: clientId,
          ChallengeResponses: {
            USERNAME: username,
            ANSWER: password,
          },
          Session: session,
        })
      );

      const nextChallenge = challengeResponse.ChallengeParameters?.challenge;
      if (challengeResponse.ChallengeName === 'CUSTOM_CHALLENGE' && nextChallenge === 'OTP_CHALLENGE') {
        setStage('otp');
        setSession(challengeResponse.Session);
        setResendDisabled(true);
        setResendTimer(10);
      } else if (challengeResponse.AuthenticationResult) {
        setTokens(challengeResponse.AuthenticationResult);
        setStage('success');
      } else {
        throw new Error(
          challengeResponse.ChallengeParameters?.failureReason || `Expected OTP_CHALLENGE after password but got ${nextChallenge || 'none'}`
        );
      }
    } catch (err) {
      setError(getErrorMessage(err.message || err.ChallengeParameters?.failureReason, 'Incorrect username or password.'));
    } finally {
      setIsLoading(false);
    }
  };

  const handleOtpSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);
    const clientId = process.env.NEXT_PUBLIC_AWS_COGNITO_APP_CLIENT_ID;
    const otpValue = otp.join('');

    try {
      const challengeResponse = await cognitoClient.send(
        new RespondToAuthChallengeCommand({
          ChallengeName: 'CUSTOM_CHALLENGE',
          ClientId: clientId,
          ChallengeResponses: {
            USERNAME: username,
            ANSWER: otpValue,
          },
          Session: session,
        })
      );

      if (challengeResponse.AuthenticationResult) {
        setTokens(challengeResponse.AuthenticationResult);
        setStage('success');
      } else if (challengeResponse.ChallengeName === 'CUSTOM_CHALLENGE') {
        const nextChallenge = challengeResponse.ChallengeParameters?.challenge;
        if (nextChallenge === 'OTP_CHALLENGE') {
          setError(getErrorMessage(challengeResponse.ChallengeParameters?.failureReason, 'Wrong OTP. Please try again.'));
          setOtp(['', '', '', '']);
          setSession(challengeResponse.Session);
          inputRefs.current[0].focus();
        } else {
          throw new Error(
            challengeResponse.ChallengeParameters?.failureReason || `Unexpected challenge: ${nextChallenge || 'none'}`
          );
        }
      } else {
        throw new Error(challengeResponse.ChallengeParameters?.failureReason || 'Unexpected response from OTP challenge');
      }
    } catch (err) {
      setError(getErrorMessage(err.message || err.ChallengeParameters?.failureReason, 'Authentication failed'));
    } finally {
      setIsLoading(false);
    }
  };

  const handleResetPasswordSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      const response = await lambdaClient.send(
        new InvokeCommand({
          FunctionName: 'Demo-Verify-Password-Reset-Otp',
          Payload: JSON.stringify({
            userName: username,
            otp: otp.join(''),
            newPassword,
          }),
        })
      );
      const result = JSON.parse(new TextDecoder().decode(response.Payload));
      if (result.statusCode === 200) {
        setError('Password reset successfully. Please log in with your new password.');
        setStage('selectFlow');
        setUsername('');
        setPassword('');
        setNewPassword('');
        setOtp(['', '', '', '']);
        setSession(null);
        setAuthFlow('PASSWORD_OTP');
      } else {
        const responseBody = JSON.parse(result.body);
        setError(getErrorMessage(responseBody.message, 'Failed to reset password.'));
        setOtp(['', '', '', '']);
        inputRefs.current[0].focus();
      }
    } catch (err) {
      console.error('AWS Error:', {
        name: err.name,
        message: err.message,
        code: err.code,
        stack: err.stack,
        details: err,
      });
      setError(getErrorMessage(err.message, 'Error resetting password.'));
    } finally {
      setIsLoading(false);
    }
  };

  const handleResendOtp = async () => {
    setError('');
    setIsLoading(true);
    const clientId = process.env.NEXT_PUBLIC_AWS_COGNITO_APP_CLIENT_ID;

    try {
      if (stage === 'otp') {
        const challengeResponse = await cognitoClient.send(
          new RespondToAuthChallengeCommand({
            ChallengeName: 'CUSTOM_CHALLENGE',
            ClientId: clientId,
            ChallengeResponses: {
              USERNAME: username,
              ANSWER: 'RESEND_OTP',
            },
            Session: session,
          })
        );

        if (challengeResponse.ChallengeName === 'CUSTOM_CHALLENGE' && challengeResponse.ChallengeParameters?.challenge === 'OTP_CHALLENGE') {
          setSession(challengeResponse.Session);
          setOtp(['', '', '', '']);
          setError('New OTP sent. Please check your SMS/email.');
          setResendDisabled(true);
          setResendTimer(10);
          inputRefs.current[0].focus();
        } else {
          throw new Error(challengeResponse.ChallengeParameters?.failureReason || 'Failed to resend OTP');
        }
      } else if (stage === 'resetPassword') {
        const response = await lambdaClient.send(
          new InvokeCommand({
            FunctionName: 'Demo-Initiate-Password-Reset',
            Payload: JSON.stringify({ userName: username }),
          })
        );
        const result = JSON.parse(new TextDecoder().decode(response.Payload));
        if (result.statusCode === 200) {
          setOtp(['', '', '', '']);
          setError('New OTP sent. Please check your SMS/email.');
          setResendDisabled(true);
          setResendTimer(10);
          inputRefs.current[0].focus();
        } else {
          const responseBody = JSON.parse(result.body);
          throw new Error(responseBody.error || 'Failed to resend OTP');
        }
      }
    } catch (err) {
      setError(getErrorMessage(err.message || err.ChallengeParameters?.failureReason, 'Failed to resend OTP. You may have reached the maximum attempts.'));
    } finally {
      setIsLoading(false);
    }
  };

  const handleForgotPassword = async () => {
    setError('');
    setIsLoading(true);

    try {
      const response = await lambdaClient.send(
        new InvokeCommand({
          FunctionName: 'Demo-Initiate-Password-Reset',
          Payload: JSON.stringify({ userName: username }),
        })
      );
      const result = JSON.parse(new TextDecoder().decode(response.Payload));
      if (result.statusCode === 200) {
        setError('Password reset OTP sent. Check your SMS/email.');
        setStage('resetPassword');
        setOtp(['', '', '', '']);
        setResendDisabled(true);
        setResendTimer(10);
      } else {
        const responseBody = JSON.parse(result.body);
        setError(getErrorMessage(responseBody.error, 'Failed to initiate password reset.'));
      }
    } catch (err) {
      console.error('AWS Error:', {
        name: err.name,
        message: err.message,
        code: err.code,
        stack: err.stack,
        details: err,
      });
      setError(getErrorMessage(err.message, 'Error initiating password reset.'));
    } finally {
      setIsLoading(false);
    }
  };

  const handleOtpChange = (index, value) => {
    if (!/^\d?$/.test(value)) return;
    const newOtp = [...otp];
    newOtp[index] = value;
    setOtp(newOtp);
    if (value && index < 3) {
      inputRefs.current[index + 1].focus();
    }
  };

  const handleOtpKeyDown = (index, e) => {
    if (e.key === 'Backspace' && !otp[index] && index > 0) {
      inputRefs.current[index - 1].focus();
    }
  };

  const handleOtpPaste = (e) => {
    e.preventDefault();
    const pastedData = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 4);
    const newOtp = ['', '', '', ''];
    for (let i = 0; i < Math.min(pastedData.length, 4); i++) {
      newOtp[i] = pastedData[i];
    }
    setOtp(newOtp);
    if (pastedData.length > 0) {
      inputRefs.current[Math.min(pastedData.length - 1, 3)].focus();
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-indigo-100 to-purple-100 p-4">
      <div className="bg-white p-8 rounded-2xl shadow-2xl w-full max-w-md transform transition-all duration-300 hover:scale-[1.02]">
        <h1 className="text-3xl font-bold mb-8 text-center text-gray-800">Secure Login</h1>

        {stage === 'selectFlow' && (
          <form onSubmit={handleFlowSelectionSubmit} className="space-y-6" aria-label="Authentication flow selection form">
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-1">
                Username
              </label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors duration-200"
                required
                aria-required="true"
                placeholder="Enter your username"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Authentication Method</label>
              <div className="flex space-x-4">
                <label className="flex items-center">
                  <input
                    type="radio"
                    value="PASSWORD_OTP"
                    checked={authFlow === 'PASSWORD_OTP'}
                    onChange={() => setAuthFlow('PASSWORD_OTP')}
                    className="mr-2"
                    aria-label="Password + OTP"
                  />
                  Password + OTP
                </label>
                <label className="flex items-center">
                  <input
                    type="radio"
                    value="OTP_ONLY"
                    checked={authFlow === 'OTP_ONLY'}
                    onChange={() => setAuthFlow('OTP_ONLY')}
                    className="mr-2"
                    aria-label="OTP Only"
                  />
                  OTP Only
                </label>
              </div>
            </div>
            <button
              type="submit"
              disabled={isLoading || !username}
              className="w-full bg-indigo-600 text-white py-3 px-4 rounded-lg hover:bg-indigo-700 disabled:bg-indigo-400 transition-colors duration-200 flex items-center justify-center"
            >
              {isLoading ? (
                <svg className="animate-spin h-5 w-5 mr-2 text-white" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path
                    className="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                  />
                </svg>
              ) : null}
              {isLoading ? 'Submitting...' : 'Continue'}
            </button>
            <button
              type="button"
              onClick={handleForgotPassword}
              disabled={isLoading || !username}
              className="w-full bg-gray-600 text-white py-3 px-4 rounded-lg hover:bg-gray-700 disabled:bg-gray-400 transition-colors duration-200 mt-2"
              aria-label="Forgot password"
            >
              {isLoading ? (
                <svg className="animate-spin h-5 w-5 mr-2 text-white" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path
                    className="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                  />
                </svg>
              ) : null}
              {isLoading ? 'Processing...' : 'Forgot Password'}
            </button>
          </form>
        )}

        {stage === 'password' && (
          <form onSubmit={handlePasswordSubmit} className="space-y-6" aria-label="Login form">
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-1">
                Username
              </label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors duration-200"
                required
                aria-required="true"
                placeholder="Enter your username"
                disabled
              />
            </div>
            <div className="relative">
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
                Password
              </label>
              <input
                id="password"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors duration-200"
                required
                aria-required="true"
                placeholder="Enter your password"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-10 text-gray-500 hover:text-gray-700"
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeSlashIcon className="h-5 w-5" /> : <EyeIcon className="h-5 w-5" />}
              </button>
            </div>
            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-indigo-600 text-white py-3 px-4 rounded-lg hover:bg-indigo-700 disabled:bg-indigo-400 transition-colors duration-200 flex items-center justify-center"
            >
              {isLoading ? (
                <svg className="animate-spin h-5 w-5 mr-2 text-white" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path
                    className="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                  />
                </svg>
              ) : null}
              {isLoading ? 'Submitting...' : 'Login'}
            </button>
            <button
              type="button"
              onClick={() => setStage('selectFlow')}
              className="w-full bg-gray-600 text-white py-3 px-4 rounded-lg hover:bg-gray-700 transition-colors duration-200 mt-2"
              aria-label="Back to flow selection"
            >
              Back to Flow Selection
            </button>
          </form>
        )}

        {stage === 'otp' && (
          <div className="space-y-6">
            <form onSubmit={handleOtpSubmit} className="space-y-6" aria-label="OTP verification form">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-3">Enter OTP Code</label>
                <div className="flex space-x-2 justify-center" onPaste={handleOtpPaste}>
                  {otp.map((digit, index) => (
                    <input
                      key={index}
                      type="text"
                      value={digit}
                      onChange={(e) => handleOtpChange(index, e.target.value)}
                      onKeyDown={(e) => handleOtpKeyDown(index, e)}
                      ref={(el) => (inputRefs.current[index] = el)}
                      maxLength={1}
                      className="w-12 h-12 text-center text-lg border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors duration-200"
                      required
                      aria-required="true"
                      aria-label={`OTP digit ${index + 1}`}
                    />
                  ))}
                </div>
                <p className="mt-3 text-sm text-gray-500 text-center">Check your SMS/email for the 4-digit OTP code</p>
              </div>
              <button
                type="submit"
                disabled={isLoading || otp.some((digit) => !digit)}
                className="w-full bg-indigo-600 text-white py-3 px-4 rounded-lg hover:bg-indigo-700 disabled:bg-indigo-400 transition-colors duration-200 flex items-center justify-center"
              >
                {isLoading ? (
                  <svg className="animate-spin h-5 w-5 mr-2 text-white" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                    />
                  </svg>
                ) : null}
                {isLoading ? 'Verifying...' : 'Submit OTP'}
              </button>
            </form>
            <button
              onClick={handleResendOtp}
              disabled={resendDisabled || isLoading}
              className="w-full bg-gray-600 text-white py-3 px-4 rounded-lg hover:bg-gray-700 disabled:bg-gray-400 transition-colors duration-200"
            >
              {resendDisabled ? `Resend OTP (${resendTimer}s)` : 'Resend OTP'}
            </button>
            <button
              type="button"
              onClick={() => setStage('selectFlow')}
              className="w-full bg-gray-600 text-white py-3 px-4 rounded-lg hover:bg-gray-700 transition-colors duration-200 mt-2"
              aria-label="Back to flow selection"
            >
              Back to Flow Selection
            </button>
          </div>
        )}

        {stage === 'resetPassword' && (
          <div className="space-y-6">
            <form onSubmit={handleResetPasswordSubmit} className="space-y-6" aria-label="Password reset form">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-3">Enter OTP Code</label>
                <div className="flex space-x-2 justify-center" onPaste={handleOtpPaste}>
                  {otp.map((digit, index) => (
                    <input
                      key={index}
                      type="text"
                      value={digit}
                      onChange={(e) => handleOtpChange(index, e.target.value)}
                      onKeyDown={(e) => handleOtpKeyDown(index, e)}
                      ref={(el) => (inputRefs.current[index] = el)}
                      maxLength={1}
                      className="w-12 h-12 text-center text-lg border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors duration-200"
                      required
                      aria-required="true"
                      aria-label={`OTP digit ${index + 1}`}
                    />
                  ))}
                </div>
                <p className="mt-3 text-sm text-gray-500 text-center">Check your SMS/email for the 4-digit OTP code</p>
              </div>
              <div className="relative">
                <label htmlFor="newPassword" className="block text-sm font-medium text-gray-700 mb-1">
                  New Password
                </label>
                <input
                  id="newPassword"
                  type={showNewPassword ? 'text' : 'password'}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors duration-200"
                  required
                  aria-required="true"
                  placeholder="Enter your new password"
                />
                <button
                  type="button"
                  onClick={() => setShowNewPassword(!showNewPassword)}
                  className="absolute right-3 top-10 text-gray-500 hover:text-gray-700"
                  aria-label={showNewPassword ? 'Hide new password' : 'Show new password'}
                >
                  {showNewPassword ? <EyeSlashIcon className="h-5 w-5" /> : <EyeIcon className="h-5 w-5" />}
                </button>
              </div>
              <button
                type="submit"
                disabled={isLoading || otp.some((digit) => !digit) || !newPassword}
                className="w-full bg-indigo-600 text-white py-3 px-4 rounded-lg hover:bg-indigo-700 disabled:bg-indigo-400 transition-colors duration-200 flex items-center justify-center"
              >
                {isLoading ? (
                  <svg className="animate-spin h-5 w-5 mr-2 text-white" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                    />
                  </svg>
                ) : null}
                {isLoading ? 'Resetting...' : 'Reset Password'}
              </button>
            </form>
            <button
              onClick={handleResendOtp}
              disabled={resendDisabled || isLoading}
              className="w-full bg-gray-600 text-white py-3 px-4 rounded-lg hover:bg-gray-700 disabled:bg-gray-400 transition-colors duration-200"
            >
              {resendDisabled ? `Resend OTP (${resendTimer}s)` : 'Resend OTP'}
            </button>
          </div>
        )}

        {error && (
          <div className="mt-6 p-4 bg-red-50 text-red-700 rounded-lg animate-in fade-in slide-in-from-top-2">
            <p className="text-sm font-medium">{error}</p>
          </div>
        )}

        {tokens && (
          <div className="mt-6 p-4 bg-green-50 text-green-700 rounded-lg animate-in fade-in slide-in-from-top-2">
            <p className="text-sm font-medium">Login successful!</p>
            <pre className="mt-2 text-xs bg-white p-3 rounded-lg overflow-auto">{JSON.stringify(tokens, null, 2)}</pre>
          </div>
        )}
      </div>
    </div>
  );
}