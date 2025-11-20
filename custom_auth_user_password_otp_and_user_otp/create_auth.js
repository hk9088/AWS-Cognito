'use strict';
const crypto = require('crypto');
const AWS = require('aws-sdk');
const sns = new AWS.SNS();
const ses = new AWS.SES({ apiVersion: '2010-12-01' });
const dynamodb = new AWS.DynamoDB.DocumentClient();
const TABLE_NAME = 'UserAuthState';
const FROM_EMAIL = 'pfh_con_engr_lead+dev1@primefocushealth.com';
const OTP_LENGTH = 4;

function generateOTP() {
  let otp = '';
  for (let i = 0; i < OTP_LENGTH; i++) {
    otp += (crypto.randomBytes(1)[0] % 10).toString();
  }
  return otp;
}

async function sendSMSviaSNS(phoneNumber, passCode) {
  const params = { 
      Message: `Your PrimeFocus Health OTP code is: ${passCode}, Do not share this code with anyone. Message & Data rates may apply.`, 
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
      Source: FROM_EMAIL_ADDRESS,
  };

  await ses.sendEmail(params).promise();
}

async function getState(userName) {
  const res = await dynamodb.get({ TableName: TABLE_NAME, Key: { userName }, ConsistentRead: true }).promise();
  return res.Item;
}

exports.handler = async (event) => {
  console.log('CREATE AUTH EVENT: ', JSON.stringify(event, null, 2));
  const session = event.request.session || [];
  const userName = event.userName;

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
      const otp = generateOTP();

      await Promise.allSettled([
        event.request.userAttributes.phone_number ? sendSMSviaSNS(event.request.userAttributes.phone_number, otp) : Promise.resolve(),
        event.request.userAttributes.email ? sendEmailviaSES(event.request.userAttributes.email, otp) : Promise.resolve(),
      ]);

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
    const otp = generateOTP();
    
    await Promise.allSettled([
      event.request.userAttributes.phone_number ? sendSMSviaSNS(event.request.userAttributes.phone_number, otp) : Promise.resolve(),
      event.request.userAttributes.email ? sendEmailviaSES(event.request.userAttributes.email, otp) : Promise.resolve(),
    ]);

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
      const otp = generateOTP();

      await Promise.allSettled([
        event.request.userAttributes.phone_number ? sendSMSviaSNS(event.request.userAttributes.phone_number, otp) : Promise.resolve(),
        event.request.userAttributes.email ? sendEmailviaSES(event.request.userAttributes.email, otp) : Promise.resolve(),
      ]);

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
