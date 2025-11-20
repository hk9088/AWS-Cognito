'use strict';
const AWS = require('aws-sdk');
const dynamodb = new AWS.DynamoDB.DocumentClient();
const TABLE_NAME = 'UserAuthState';
const MAX_RESEND = 4;

async function deleteState(userName) {
  await dynamodb.delete({
    TableName: TABLE_NAME,
    Key: { userName },
  }).promise();
}

exports.handler = async (event) => {
  console.log('RECEIVED event: ', JSON.stringify(event, null, 2));
  const session = event.request.session || [];
  const userName = event.userName;

  // Step 1: Password challenge
  if (session.length === 0) {
    event.response.issueTokens = false;
    event.response.failAuthentication = false;
    event.response.challengeName = 'CUSTOM_CHALLENGE';
  }
  // Step 2: OTP challenge after password
  else if (
    session.length === 1 &&
    session[0].challengeName === 'CUSTOM_CHALLENGE' &&
    session[0].challengeResult === true &&
    session[0].challengeMetadata === 'PASSWORD_CHALLENGE'
  ) {
    event.response.issueTokens = false;
    event.response.failAuthentication = false;
    event.response.challengeName = 'CUSTOM_CHALLENGE';
  }
  // Step 3: OTP correct → issue tokens
  else if (
    session.length >= 2 &&
    session[session.length - 1].challengeName === 'CUSTOM_CHALLENGE' &&
    session[session.length - 1].challengeResult === true &&
    session[session.length - 1].challengeMetadata === 'OTP_CHALLENGE'
  ) {
    await deleteState(userName);
    event.response.issueTokens = true;
    event.response.failAuthentication = false;
  }
  // Retry or failure handling
  else {
    const last = session[session.length - 1];

    if (last.challengeName === 'CUSTOM_CHALLENGE') {
      // wrong password → fail immediately
      if (last.challengeMetadata === 'PASSWORD_CHALLENGE' && last.challengeResult === false) {
        await deleteState(userName);
        event.response.issueTokens = false;
        event.response.failAuthentication = true;
        event.response.publicChallengeParameters = { failureReason: 'INVALID_PASSWORD' }; // Add failure reason
      } 
      // wrong OTP → allow retry unless max resends exceeded
      else if (last.challengeMetadata === 'OTP_CHALLENGE') {
        const stateRes = await dynamodb.get({ TableName: TABLE_NAME, Key: { userName } }).promise();
        const state = stateRes.Item;

        if (state && (state.resendCount >= MAX_RESEND)) {
          await deleteState(userName);
          event.response.issueTokens = false;
          event.response.failAuthentication = true;
          event.response.publicChallengeParameters = { failureReason: 'MAX_OTP_RESEND_ATTEMPTS_EXCEEDED' }; // Add failure reason
        } else {
          event.response.issueTokens = false;
          event.response.failAuthentication = false;
          event.response.challengeName = 'CUSTOM_CHALLENGE';
        }
      } 
      // anything else → fail
      else {
        await deleteState(userName);
        event.response.issueTokens = false;
        event.response.failAuthentication = true;
        event.response.publicChallengeParameters = { failureReason: 'UNKNOWN_ERROR' }; // Add failure reason
      }
    } else {
      await deleteState(userName);
      event.response.issueTokens = false;
      event.response.failAuthentication = true;
      event.response.publicChallengeParameters = { failureReason: 'INVALID_CHALLENGE_STATE' }; // Add failure reason
    }
  }

  console.log('RETURNED event: ', JSON.stringify(event, null, 2));
  return event;
};
