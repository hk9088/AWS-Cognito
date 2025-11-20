"use strict";

const { CognitoIdentityProviderClient, AdminInitiateAuthCommand } = require('@aws-sdk/client-cognito-identity-provider');

const client = new CognitoIdentityProviderClient();

exports.handler = async (event) => {
  const username = event.userName;
  const password = event.request.challengeAnswer;  // Password provided by client

  if (!password) {
    event.response.answerCorrect = false;
    return event;
  }

  const params = {
    UserPoolId: event.userPoolId,  // Automatically provided by Cognito
    ClientId: event.callerContext.clientId,  // Automatically provided
    AuthFlow: 'ADMIN_USER_PASSWORD_AUTH',
    AuthParameters: {
      USERNAME: username,
      PASSWORD: password
    }
  };

  // If your app client has a secret, compute and add SECRET_HASH here
  // Example: params.AuthParameters.SECRET_HASH = computeSecretHash(username, clientId, clientSecret);

  try {
    await client.send(new AdminInitiateAuthCommand(params));
    event.response.answerCorrect = true;  // Verification succeeded
  } catch (error) {
    console.error(error);
    if (error.name === 'NotAuthorizedException' || error.name === 'UserNotFoundException') {
      event.response.answerCorrect = false;  // Wrong username/password
    } else {
      throw error;  // Other errors (e.g., config issues)
    }
  }

  return event;
};

// Optional: Function to compute SECRET_HASH if needed
function computeSecretHash(username, clientId, clientSecret) {
  const crypto = require('crypto');
  const message = username + clientId;
  const hmac = crypto.createHmac('sha256', clientSecret);
  hmac.update(message);
  return hmac.digest('base64');
}