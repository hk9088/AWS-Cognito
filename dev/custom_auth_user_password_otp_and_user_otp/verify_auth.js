'use strict';
const { CognitoIdentityProviderClient, AdminInitiateAuthCommand } = require('@aws-sdk/client-cognito-identity-provider');
const AWS = require('aws-sdk');
const dynamodb = new AWS.DynamoDB.DocumentClient();
const client = new CognitoIdentityProviderClient();
const TABLE_NAME = 'UserAuthState';
const MAX_RESEND = 4;

async function getState(userName) {
 const res = await dynamodb.get({ TableName: TABLE_NAME, Key: { userName } }).promise();
 return res.Item;
}

exports.handler = async (event) => {
 console.log('RECEIVED Event: ', JSON.stringify(event, null, 2));
 try {
   const metadata = event.request.privateChallengeParameters.challengeMetadata;
   const userName = event.userName;
   const answer = event.request.challengeAnswer;

   // SELECT_AUTH_FLOW challenge
   if (metadata === 'SELECT_AUTH_FLOW') {
     if (answer !== 'PASSWORD_OTP' && answer !== 'OTP_ONLY') {
       event.response.answerCorrect = false;
       console.log('Invalid auth flow selected');
       console.log('VERIFY AUTH RETURNED Event: ', JSON.stringify(event, null, 2));
       return event;
     }
     await dynamodb.put({
       TableName: TABLE_NAME,
       Item: {
         userName,
         authFlow: answer,
         resendCount: 0,
         lastSentResendCount: 0,
         otpAttempts: 0,
       },
     }).promise();
     event.response.answerCorrect = true;
     console.log(`Auth flow selected: ${answer}`);
   }
   // PASSWORD_CHALLENGE
   else if (metadata === 'PASSWORD_CHALLENGE') {
     if (!answer) {
       event.response.answerCorrect = false;
       console.log('VERIFY AUTH RETURNED Event: ', JSON.stringify(event, null, 2));
       return event;
     }
     try {
       await client.send(
         new AdminInitiateAuthCommand({
           UserPoolId: event.userPoolId,
           ClientId: event.callerContext.clientId,
           AuthFlow: 'ADMIN_USER_PASSWORD_AUTH',
           AuthParameters: { USERNAME: userName, PASSWORD: answer },
         })
       );
       event.response.answerCorrect = true;
     } catch {
       event.response.answerCorrect = false;
     }
   }
   // OTP_CHALLENGE
   else if (metadata === 'OTP_CHALLENGE') {
     const state = await getState(userName);
     if (!state) {
       event.response.answerCorrect = false;
       console.log('VERIFY AUTH RETURNED Event: ', JSON.stringify(event, null, 2));
       return event;
     }
     if (answer === 'RESEND_OTP') {
       if (state.resendCount >= MAX_RESEND) {
         event.response.answerCorrect = false;
         console.log('Max resend attempts reached');
         throw new Error('MAX_OTP_RESEND_ATTEMPTS_EXCEEDED');
       } else {
         await dynamodb.update({
           TableName: TABLE_NAME,
           Key: { userName },
           UpdateExpression: 'set resendCount = resendCount + :inc, otpAttempts = :zero',
           ExpressionAttributeValues: { ':inc': 1, ':zero': 0 },
         }).promise();
         event.response.answerCorrect = false;
         console.log('RESEND_OTP accepted');
       }
     } else if (answer === state.otp) {
       event.response.answerCorrect = true;
       console.log('Correct OTP entered');
     } else {
       await dynamodb.update({
         TableName: TABLE_NAME,
         Key: { userName },
         UpdateExpression: 'set otpAttempts = otpAttempts + :inc',
         ExpressionAttributeValues: { ':inc': 1 },
       }).promise();
       event.response.answerCorrect = false;
       console.log('Wrong OTP');
     }
   } else {
     event.response.answerCorrect = false;
   }
 } catch (err) {
   console.error('Error in VerifyAuthChallenge:', err);
   throw err;
 }

 console.log('VERIFY AUTH RETURNED Event: ', JSON.stringify(event, null, 2));
 return event;
};