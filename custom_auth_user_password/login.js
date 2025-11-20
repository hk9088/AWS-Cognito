'use client';

import React, { useState } from 'react';
import { CognitoIdentityProviderClient, InitiateAuthCommand, RespondToAuthChallengeCommand } from '@aws-sdk/client-cognito-identity-provider';

// Initialize Cognito client with region from environment variable
const client = new CognitoIdentityProviderClient({ region: process.env.NEXT_PUBLIC_AWS_COGNITO_REGION });

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [tokens, setTokens] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    setTokens(null);
    setIsLoading(true);

    const clientId = process.env.NEXT_PUBLIC_AWS_COGNITO_APP_CLIENT_ID;

    if (!clientId || !process.env.NEXT_PUBLIC_AWS_COGNITO_REGION) {
      setError('Missing environment variables. Please check your configuration.');
      setIsLoading(false);
      return;
    }

    try {
      // Step 1: Initiate custom auth
      const initiateParams = {
        AuthFlow: 'CUSTOM_AUTH',
        ClientId: clientId,
        AuthParameters: {
          USERNAME: username,
        },
      };
      const initiateResponse = await client.send(new InitiateAuthCommand(initiateParams));

      if (initiateResponse.ChallengeName !== 'CUSTOM_CHALLENGE') {
        throw new Error(`Expected CUSTOM_CHALLENGE but got ${initiateResponse.ChallengeName || 'none'}`);
      }

      // Step 2: Respond to custom challenge with password
      const challengeParams = {
        ChallengeName: 'CUSTOM_CHALLENGE',
        ClientId: clientId,
        ChallengeResponses: {
          USERNAME: username,
          ANSWER: password,
        },
        Session: initiateResponse.Session,
      };
      const challengeResponse = await client.send(new RespondToAuthChallengeCommand(challengeParams));

      // Step 3: Handle successful authentication
      setTokens(challengeResponse.AuthenticationResult);
    } catch (err) {
      setError(err.message || 'Authentication failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <div className="bg-white p-8 rounded-lg shadow-lg w-full max-w-md">
        <h1 className="text-2xl font-bold mb-6 text-center">Login with Cognito</h1>
        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label htmlFor="username" className="block text-sm font-medium text-gray-700">
              Username
            </label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
              required
            />
          </div>
          <div>
            <label htmlFor="password" className="block text-sm font-medium text-gray-700">
              Password
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
              required
            />
          </div>
          <button
            type="submit"
            disabled={isLoading}
            className="w-full bg-indigo-600 text-white py-2 px-4 rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:bg-indigo-400"
          >
            {isLoading ? 'Logging in...' : 'Login'}
          </button>
        </form>
        {error && (
          <div className="mt-4 p-3 bg-red-100 text-red-700 rounded-md">
            {error}
          </div>
        )}
        {tokens && (
          <div className="mt-4 p-3 bg-green-100 text-green-700 rounded-md">
            <p>Login successful!</p>
            <pre className="text-sm overflow-auto">
              {JSON.stringify(tokens, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}