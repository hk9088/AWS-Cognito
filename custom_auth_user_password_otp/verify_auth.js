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

        // PASSWORD challenge
        if (metadata === 'PASSWORD_CHALLENGE') {
            if (!answer) {
                event.response.answerCorrect = false;
                return event;
            }

            try {
                await client.send(new AdminInitiateAuthCommand({
                    UserPoolId: event.userPoolId,
                    ClientId: event.callerContext.clientId,
                    AuthFlow: 'ADMIN_USER_PASSWORD_AUTH',
                    AuthParameters: { USERNAME: userName, PASSWORD: answer },
                }));
                event.response.answerCorrect = true;
            } catch {
                event.response.answerCorrect = false;
            }
        }
        // OTP challenge
        else if (metadata === 'OTP_CHALLENGE') {
            const state = await getState(userName);
            if (!state) {
                event.response.answerCorrect = false;
                return event;
            }

            // Resend OTP request
            if (answer === 'RESEND_OTP') {
                if (state.resendCount >= MAX_RESEND) {
                    event.response.answerCorrect = false;
                    console.log('Max resend attempts reached');
                    throw new Error('MAX_OTP_RESEND_ATTEMPTS_EXCEEDED');
                } else {
                    try {
                        await dynamodb.update({
                            TableName: TABLE_NAME,
                            Key: { userName },
                            UpdateExpression: 'set resendCount = resendCount + :inc, otpAttempts = :zero',
                            ExpressionAttributeValues: { ':inc': 1, ':zero': 0 },
                        }).promise();
                        event.response.answerCorrect = false; // triggers CreateAuthChallenge to generate new OTP
                        console.log('RESEND_OTP accepted');
                    } catch (e) {
                        console.log('Error Updating DB: ',e);
                        throw e;
                    }
                }
            }
            // Normal OTP entry
            else if (answer === state.otp) {
                event.response.answerCorrect = true;
                console.log('Correct OTP entered');
            } else {
                // Wrong OTP → increment otpAttempts
                try {
                    await dynamodb.update({
                        TableName: TABLE_NAME,
                        Key: { userName },
                        UpdateExpression: 'set otpAttempts = otpAttempts + :inc',
                        ExpressionAttributeValues: { ':inc': 1 },
                    }).promise();
                    event.response.answerCorrect = false;
                    console.log('Wrong OTP');
                } catch (e) {
                    console.log('Error Updating DB: ',e);
                    throw e;
                }
            }
        } else {
            event.response.answerCorrect = false;
        }

    } catch (err) {
        console.error('Error in VerifyAuthChallenge:', err);
        throw err;
    }

    console.log('RETURNED Event: ', JSON.stringify(event, null, 2));
    return event;
};
