'use strict';
const crypto = require('crypto');
const AWS = require('aws-sdk');
const sns = new AWS.SNS();
const ses = new AWS.SES({ apiVersion: '2010-12-01' });
const dynamodb = new AWS.DynamoDB.DocumentClient();

const FROM_EMAIL_ADDRESS = 'pfh_con_engr_lead+dev1@primefocushealth.com';
const TABLE_NAME = 'UserPasswordReset';
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

exports.handler = async (event = {}) => {
 console.log('RECEIVED event:', JSON.stringify(event, null, 2));
 const { userName, userPoolId } = event.body ? JSON.parse(event.body) : event;

 if (!userName || !userPoolId) {
   console.log('Missing required fields:', { userName, userPoolId });
   return {
     statusCode: 400,
     body: JSON.stringify({ message: 'userName, userPoolId is required' }),
   };
 }

 const passCode = generateOTP();
 const ttl = Math.floor(Date.now() / 1000) + 300;

 const dynamoParams = {
   TableName: TABLE_NAME,
   Item: { userName, otp: passCode, ttl },
 };

 try {
   const cognito = new AWS.CognitoIdentityServiceProvider();
   console.log('Fetching user attributes for:', userName);
   const user = await cognito
     .adminGetUser({
       UserPoolId: userPoolId,
       Username: userName,
     })
     .promise();

   const userAttributes = user.UserAttributes.reduce((acc, attr) => {
     acc[attr.Name] = attr.Value;
     return acc;
   }, {});
   console.log('User Attributes:', JSON.stringify(userAttributes, null, 2));

   // console.log('Storing OTP in DynamoDB:', dynamoParams);
   await dynamodb.put(dynamoParams).promise();
   console.log('OTP stored successfully');

   const deliveryPromises = [];
   if (userAttributes.phone_number) {
     console.log('Sending SMS to:', userAttributes.phone_number);
     deliveryPromises.push(sendSMSviaSNS(userAttributes.phone_number, passCode));
   } else {
     console.log('No phone_number found for user');
   }
   if (userAttributes.email) {
     console.log('Sending email to:', userAttributes.email);
     deliveryPromises.push(sendEmailviaSES(userAttributes.email, passCode));
   } else {
     console.log('No email found for user');
   }

   const results = await Promise.allSettled(deliveryPromises);
   console.log('Delivery results:', JSON.stringify(results, null, 2));

   return {
     statusCode: 200,
     body: JSON.stringify({ message: 'OTP sent successfully' }),
   };
 } catch (error) {
   console.error('Error:', JSON.stringify({ message: error.message, code: error.code, stack: error.stack }, null, 2));
   return {
     statusCode: 500,
     body: JSON.stringify({ message: 'Error sending OTP', error: error.message, code: error.code }),
   };
 }
};