'use strict';
const crypto = require('crypto');
const AWS = require('aws-sdk');
const sns = new AWS.SNS();
const ses = new AWS.SES({ apiVersion: '2010-12-01' });
const dynamodb = new AWS.DynamoDB.DocumentClient();
const TABLE_NAME = 'UserAuthState';
const FROM_EMAIL = 'pfh_con_engr_devops@primefocushealth.com';
const OTP_LENGTH = 4;

const TEST_PHONE_NUMBERS = new Set([
  '+15550101010',
  '+18001001000',
  '+18001001001',
  '+18001001002',
  '+18001001003',
  '+18002002000',
  '+18002002001',
  '+18002002002',
  '+18002002003',
  '+18003003000',
  '+18003003001',
  '+18003003002',
  '+18003003003'
]);

function isTestPhoneNumber(phoneNumber) {
  return TEST_PHONE_NUMBERS.has(phoneNumber);
}

const cognitoIdp = new AWS.CognitoIdentityServiceProvider();

async function isUserInProviderGroup(userPoolId, userName) {
  const groups = await cognitoIdp.adminListGroupsForUser({
    UserPoolId: userPoolId,
    Username: userName
  }).promise();

  return groups.Groups.some(group => group.GroupName.includes('PROVIDER'));
}

function generateOTP(phoneNumber) {
  if (isTestPhoneNumber(phoneNumber)) {
    console.log(`Using fixed OTP for test number: ${phoneNumber}`);
    return '1234';
  }

 let otp = '';
 for (let i = 0; i < OTP_LENGTH; i++) {
   otp += (crypto.randomBytes(1)[0] % 10).toString();
 }
 return otp;
}

async function sendSMSviaSNS(phoneNumber, passCode) {
 const params = {
     Message: `Your PrimeFocus Health OTP code is: ${passCode}, Do not share this code with anyone. Message & Data rates may apply.
yRXy5cUWIP6`,
     PhoneNumber: phoneNumber
 };
 await sns.publish(params).promise();
}

async function sendEmailviaSES(emailAddress, passCode) {
 const params = {
     Destination: {
         ToAddresses: [emailAddress]
     },
     Message: {
         Body: {
             Html: {
                 Charset: "UTF-8",
                 Data: `<html><body>
                         <p>Dear User,</p>
                         <p>Your one-time password (OTP) code is: <b>${passCode}</b></p>
                         <p>This code is valid for the next 10 minutes. Please do not share this code with anyone.</p>
                         <p>If you did not request this, please contact PrimeFocus Health support immediately.</p>
                         <p>Thank you,<br/>PrimeFocus Health Team</p>
                         <hr/>
                         <p style="font-size:small; color:gray;">
                           This email may contain confidential information and is intended only for the recipient.
                         </p>
                        </body></html>`
             },
             Text: {
                 Charset: "UTF-8",
                 Data: `Dear User,\n\nYour one-time password (OTP) code is: ${passCode}\n\nThis code is valid for the next 10 minutes. Please do not share this code with anyone.\n\nIf you did not request this, please contact PrimeFocus Health support immediately.\n\nThank you,\nPrimeFocus Health Team\n\n---\nThis email may contain confidential information and is intended only for the recipient.`
             }
         },
         Subject: {
             Charset: "UTF-8",
             Data: "PrimeFocus Health OTP Code"
         }
     },
     Source: FROM_EMAIL,
 };

 await ses.sendEmail(params).promise();
}

async function sendOTP(otp, event, userName, phoneNumber) {
  if (isTestPhoneNumber(phoneNumber)) {
    console.log(`Skipping sending otp, Using fixed OTP for test number: ${phoneNumber}`);
    return;
  }

  const { userPoolId, request: { userAttributes } } = event;
  const inProviderGroup = await isUserInProviderGroup(userPoolId, userName);

  const sendSMS = !inProviderGroup && userAttributes.phone_number
    ? sendSMSviaSNS(userAttributes.phone_number, otp)
        .then(() => true)
        .catch(err => {
          console.error('SMS failed:', err);
          return false;
        })
    : Promise.resolve(false);

  const sendEmail = userAttributes.email
    ? sendEmailviaSES(userAttributes.email, otp)
        .then(() => true)
        .catch(err => {
          console.error('Email failed:', err);
          return false;
        })
    : Promise.resolve(false);

  const [smsSuccess, emailSuccess] = await Promise.all([sendSMS, sendEmail]);

  if (!smsSuccess && !emailSuccess) {
    throw new Error('Failed to send OTP via both SMS and Email');
  }
}

async function getState(userName) {
 const res = await dynamodb.get({ TableName: TABLE_NAME, Key: { userName }, ConsistentRead: true }).promise();
 return res.Item;
}

exports.handler = async (event) => {
 console.log('CREATE AUTH EVENT: ', JSON.stringify(event, null, 2));
 const session = event.request.session || [];
 const userName = event.userName;
 const phoneNumber = event.request.userAttributes.phone_number;

 // First step: SELECT_AUTH_FLOW
 if (session.length === 0) {
   event.response.publicChallengeParameters = { challenge: 'SELECT_AUTH_FLOW' };
   event.response.privateChallengeParameters = { challengeMetadata: 'SELECT_AUTH_FLOW' };
   event.response.challengeMetadata = 'SELECT_AUTH_FLOW';
   console.log('CREATE AUTH RETURN: ', JSON.stringify(event, null, 2));
   return event;
 }

 // After SELECT_AUTH_FLOW success → next challenge
 if (
   session.length === 1 &&
   session[0].challengeMetadata === 'SELECT_AUTH_FLOW' &&
   session[0].challengeResult === true
 ) {
   const state = await getState(userName);
   if (state.authFlow === 'PASSWORD_OTP') {
     event.response.publicChallengeParameters = { challenge: 'PASSWORD_CHALLENGE' };
     event.response.privateChallengeParameters = { challengeMetadata: 'PASSWORD_CHALLENGE' };
     event.response.challengeMetadata = 'PASSWORD_CHALLENGE';
   }
   else if (state.authFlow === 'OTP_ONLY') {
     const otp = generateOTP(phoneNumber);
     await sendOTP(otp, event, userName, phoneNumber);
     
     await dynamodb.update({
       TableName: TABLE_NAME,
       Key: { userName },
       UpdateExpression: 'set otp = :otp, resendCount = :zero, lastSentResendCount = :zero, otpAttempts = :zero',
       ExpressionAttributeValues: { ':otp': otp, ':zero': 0 },
     }).promise();
     event.response.publicChallengeParameters = { challenge: 'OTP_CHALLENGE' };
     event.response.privateChallengeParameters = { challengeMetadata: 'OTP_CHALLENGE' };
     event.response.challengeMetadata = 'OTP_CHALLENGE';
   }
   console.log('CREATE AUTH RETURN: ', JSON.stringify(event, null, 2));
   return event;
 }

 // After PASSWORD success → now OTP
 if (
   session.length === 2 &&
   session[1].challengeMetadata === 'PASSWORD_CHALLENGE' &&
   session[1].challengeResult === true
 ) {
   const otp = generateOTP(phoneNumber);
   await sendOTP(otp, event, userName, phoneNumber);

   await dynamodb.update({
     TableName: TABLE_NAME,
     Key: { userName },
     UpdateExpression: 'set otp = :otp, resendCount = :zero, lastSentResendCount = :zero, otpAttempts = :zero',
     ExpressionAttributeValues: { ':otp': otp, ':zero': 0 },
   }).promise();
   event.response.publicChallengeParameters = { challenge: 'OTP_CHALLENGE' };
   event.response.privateChallengeParameters = { challengeMetadata: 'OTP_CHALLENGE' };
   event.response.challengeMetadata = 'OTP_CHALLENGE';
   console.log('CREATE AUTH RETURN: ', JSON.stringify(event, null, 2));
   return event;
 }

 // Retry OTP (wrong attempt or resend)
 const last = session[session.length - 1];
 if (last.challengeMetadata === 'OTP_CHALLENGE') {
   const state = await getState(userName);
   if (state && state.resendCount > state.lastSentResendCount) {
     const otp = generateOTP(phoneNumber);
     await sendOTP(otp, event, userName, phoneNumber);

     await dynamodb.update({
       TableName: TABLE_NAME,
       Key: { userName },
       UpdateExpression: 'set otp = :otp, lastSentResendCount = :resend',
       ExpressionAttributeValues: { ':otp': otp, ':resend': state.resendCount },
     }).promise();
   }
   event.response.publicChallengeParameters = { challenge: 'OTP_CHALLENGE' };
   event.response.privateChallengeParameters = { challengeMetadata: 'OTP_CHALLENGE' };
   event.response.challengeMetadata = 'OTP_CHALLENGE';
   console.log('CREATE AUTH RETURN: ', JSON.stringify(event, null, 2));
   return event;
 }

 console.log('CREATE AUTH RETURN: ', JSON.stringify(event, null, 2));
 return event;
};