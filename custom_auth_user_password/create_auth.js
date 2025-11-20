exports.handler = async (event) => {
  if (event.request.challengeName === 'CUSTOM_CHALLENGE') {
    event.response.publicChallengeParameters = {
      challenge: 'Provide your password'
    };
  }
  return event;
};