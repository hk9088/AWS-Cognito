'use strict';
const crypto = require('crypto');
const AWS = require('aws-sdk');
const sns = new AWS.SNS();
const ses = new AWS.SES({ apiVersion: '2010-12-01' });
const dynamodb = new AWS.DynamoDB.DocumentClient();

const FROM_EMAIL_ADDRESS = 'pfh_con_engr_lead+dev1@primefocushealth.com';
const TABLE_NAME = 'UserAuthState';
const OTP_LENGTH = 4;

function generateOTP() {
  let otp = '';
  for (let i = 0; i < OTP_LENGTH; i++) otp += (crypto.randomBytes(1)[0] % 10).toString();
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
  const res = await dynamodb.get({ TableName: TABLE_NAME, Key: { userName }, ConsistentRead: true, }).promise();
  return res.Item;
}

exports.handler = async (event = {}) => {
  console.log('RECEIVED event: ', JSON.stringify(event, null, 2));
  const session = event.request.session || [];
  const userName = event.userName;

  try {
    // Step 1 → PASSWORD challenge
    if (session.length === 0) {
      event.response.publicChallengeParameters = { challenge: 'PASSWORD_CHALLENGE' };
      event.response.privateChallengeParameters = { challengeMetadata: 'PASSWORD_CHALLENGE' };
      event.response.challengeMetadata = 'PASSWORD_CHALLENGE';
    }
    // Step 2 → OTP challenge after password
    else if (
      session.length === 1 &&
      session[0].challengeName === 'CUSTOM_CHALLENGE' &&
      session[0].challengeResult === true &&
      session[0].challengeMetadata === 'PASSWORD_CHALLENGE'
    ) {
      const passCode = generateOTP();

      await Promise.allSettled([
        event.request.userAttributes.phone_number ? sendSMSviaSNS(event.request.userAttributes.phone_number, passCode) : Promise.resolve(),
        event.request.userAttributes.email ? sendEmailviaSES(event.request.userAttributes.email, passCode) : Promise.resolve(),
      ]);

      await dynamodb.put({
        TableName: TABLE_NAME,
        Item: {
          userName,
          otp: passCode,
          resendCount: 0,
          lastSentResendCount: 0,
          otpAttempts: 0
        },
      }).promise();

      event.response.publicChallengeParameters = { challenge: 'OTP_CHALLENGE' };
      event.response.privateChallengeParameters = { challengeMetadata: 'OTP_CHALLENGE' };
      event.response.challengeMetadata = 'OTP_CHALLENGE';
    }
    // Retry or resend
    else {
      const last = session[session.length - 1];
      event.response.publicChallengeParameters = { challenge: 'OTP_CHALLENGE' };
      event.response.privateChallengeParameters = { challengeMetadata: last.challengeMetadata };
      event.response.challengeMetadata = last.challengeMetadata;

      const state = await getState(userName);

      if (state && last.challengeMetadata === 'OTP_CHALLENGE') {
        // Only generate new OTP if resendCount > lastSentResendCount
        if (state.resendCount > (state.lastSentResendCount || 0)) {
          const newCode = generateOTP();

          await Promise.allSettled([
            event.request.userAttributes.phone_number ? sendSMSviaSNS(event.request.userAttributes.phone_number, newCode) : Promise.resolve(),
            event.request.userAttributes.email ? sendEmailviaSES(event.request.userAttributes.email, newCode) : Promise.resolve(),
          ]);

          // Update DynamoDB: store new OTP and lastSentResendCount
          await dynamodb.update({
            TableName: TABLE_NAME,
            Key: { userName },
            UpdateExpression: 'set otp = :otp, lastSentResendCount = :resendCount',
            ExpressionAttributeValues: { ':otp': newCode, ':resendCount': state.resendCount },
          }).promise();

          console.log(`New OTP sent for ${userName}`);
        } else {
          console.log('No new OTP generated; this is a wrong OTP retry');
        }
      }
    }

    console.log('RETURNED event: ', JSON.stringify(event, null, 2));
    return event;
  } catch (err) {
    console.error('Error in CreateAuthChallenge:', err);
    throw err;
  }
};
