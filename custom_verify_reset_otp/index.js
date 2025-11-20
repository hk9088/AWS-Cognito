'use strict';
const AWS = require('aws-sdk');
const dynamodb = new AWS.DynamoDB.DocumentClient();
const cognito = new AWS.CognitoIdentityServiceProvider();

const TABLE_NAME = 'UserPasswordReset';

exports.handler = async (event = {}) => {
 console.log('RECEIVED event: ', JSON.stringify(event, null, 2));
 const { userName, userPoolId, otp, newPassword } = event.body ? JSON.parse(event.body) : event;

 // Validate input
 if (!userName || !userPoolId || !otp || !newPassword) {
   console.log('Missing required fields:', { userName, userPoolId, otp, newPassword });
   return {
     statusCode: 400,
     body: JSON.stringify({ message: 'userName, userPoolId, otp, and newPassword are required' }),
   };
 }

 // Basic password validation (extend as per Cognito policy)
 if (newPassword.length < 8) {
   console.log('Password validation failed: length < 8');
   return {
     statusCode: 400,
     body: JSON.stringify({ message: 'Password must be at least 8 characters long' }),
   };
 }

 // Verify OTP in DynamoDB
 const dynamoParams = {
   TableName: TABLE_NAME,
   Key: { userName },
 };

 try {
   // console.log('Querying DynamoDB with params:', JSON.stringify(dynamoParams, null, 2));
   const result = await dynamodb.get(dynamoParams).promise();
   // console.log('DynamoDB result:', JSON.stringify(result, null, 2));

   if (!result.Item || result.Item.otp !== otp || result.Item.ttl < Math.floor(Date.now() / 1000)) {
     console.log('Invalid or expired OTP for user:', userName);
     return {
       statusCode: 400,
       body: JSON.stringify({ message: 'Invalid or expired OTP' }),
     };
   }

   // Update password in Cognito
   const cognitoParams = {
     UserPoolId: userPoolId,
     Username: userName,
     Password: newPassword,
     Permanent: true,
   };
  
   console.log('Updating Cognito password with params:', JSON.stringify(cognitoParams, null, 2));
   try {
     await cognito.adminSetUserPassword(cognitoParams).promise();
     console.log('Password reset successfully for user:', userName);
   }
   catch (cognitoError) {
     console.error('Cognito error:', JSON.stringify({ message: cognitoError.message, code: cognitoError.code }, null, 2));
     if (cognitoError.code === 'InvalidPasswordException') {
       return {
         statusCode: 400,
         body: JSON.stringify({ message: 'Password does not meet requirements' }),
       };
     }
     else if (cognitoError.code === 'UserNotFoundException') {
       return {
         statusCode: 404,
         body: JSON.stringify({ message: 'User not found' }),
       };
     }
     throw cognitoError;
   }

   // Delete OTP after verification
   console.log('Deleting OTP for user:', userName);
   await dynamodb.delete(dynamoParams).promise();
   console.log('OTP deleted successfully for user:', userName);

   return {
     statusCode: 200,
     body: JSON.stringify({ message: 'Password reset successfully' }),
   };
 } catch (error) {
   console.error('Unexpected error:', JSON.stringify({ message: error.message, code: error.code, stack: error.stack }, null, 2));
   return {
     statusCode: 500,
     body: JSON.stringify({ message: 'Error resetting password', error: error.message }),
   };
 }
};