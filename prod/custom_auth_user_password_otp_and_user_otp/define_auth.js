'use strict';
const AWS = require('aws-sdk');
const dynamodb = new AWS.DynamoDB.DocumentClient();
const TABLE_NAME = 'UserAuthState';
const MAX_RESEND = 4;

async function getState(userName) {
 const res = await dynamodb.get({ TableName: TABLE_NAME, Key: { userName } }).promise();
 return res.Item;
}

async function deleteState(userName) {
 await dynamodb.delete({ TableName: TABLE_NAME, Key: { userName } }).promise();
}

exports.handler = async (event) => {
 console.log('DEFINE AUTH EVENT: ', JSON.stringify(event, null, 2));
 const session = event.request.session || [];
 const userName = event.userName;

 // 1. First login attempt → ask for auth flow selection
 if (session.length === 0) {
   event.response.issueTokens = false;
   event.response.failAuthentication = false;
   event.response.challengeName = 'CUSTOM_CHALLENGE';
   console.log('DEFINE AUTH RETURN: ', JSON.stringify(event, null, 2));
   return event;
 }

 // 2. After flow selection
 if (
   session.length === 1 &&
   session[0].challengeName === 'CUSTOM_CHALLENGE' &&
   session[0].challengeResult === true &&
   session[0].challengeMetadata === 'SELECT_AUTH_FLOW'
 ) {
   // just tell Cognito: issue another CUSTOM_CHALLENGE
   event.response.issueTokens = false;
   event.response.failAuthentication = false;
   event.response.challengeName = 'CUSTOM_CHALLENGE';
   console.log('DEFINE AUTH RETURN: ', JSON.stringify(event, null, 2));
   return event;
 }

 // 3. After successful password in PASSWORD_OTP flow → now ask OTP
 if (
   session.length === 2 &&
   session[1].challengeName === 'CUSTOM_CHALLENGE' &&
   session[1].challengeMetadata === 'PASSWORD_CHALLENGE'
 ) {
   event.response.issueTokens = false;
   event.response.failAuthentication = false;

   // 3a. After wrong password → fail immediately
   if(session[1].challengeResult === false){
     await deleteState(userName);
     event.response.failAuthentication = true;
   }

   event.response.challengeName = 'CUSTOM_CHALLENGE';
   console.log('DEFINE AUTH RETURN: ', JSON.stringify(event, null, 2));
   return event;
 }

 // 4. Successful OTP → issue tokens
 const last = session[session.length - 1];
 if (
   last.challengeName === 'CUSTOM_CHALLENGE' &&
   last.challengeResult === true &&
   last.challengeMetadata === 'OTP_CHALLENGE'
 ) {
   await deleteState(userName);
   event.response.issueTokens = true;
   event.response.failAuthentication = false;
   console.log('DEFINE AUTH RETURN: ', JSON.stringify(event, null, 2));
   return event;
 }

 // 5. Retry/failure
 if (
   last.challengeName === 'CUSTOM_CHALLENGE' &&
   last.challengeMetadata === 'OTP_CHALLENGE' &&
   last.challengeResult === false
 ) {
   const state = await getState(userName);
   if (state && state.resendCount >= MAX_RESEND) {
     await deleteState(userName);
     event.response.issueTokens = false;
     event.response.failAuthentication = true;
   } else {
     // allow retry
     event.response.issueTokens = false;
     event.response.failAuthentication = false;
     event.response.challengeName = 'CUSTOM_CHALLENGE';
   }
   console.log('DEFINE AUTH RETURN: ', JSON.stringify(event, null, 2));
   return event;
 }

 // default → fail
 event.response.issueTokens = false;
 event.response.failAuthentication = true;
 await deleteState(userName);

 console.log('DEFINE AUTH RETURN: ', JSON.stringify(event, null, 2));
 return event;
};
