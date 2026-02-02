export const handler = async (event) => {
  // Include custom attribute in access token
  event.response = {
    claimsAndScopeOverrideDetails: {
        accessTokenGeneration: {
            claimsToAddOrOverride: {
                "clientId": event.request.userAttributes["custom:clientId"]
            }
        },
        idTokenGeneration: {
            claimsToAddOrOverride: {
                "clientId": event.request.userAttributes["custom:clientId"]
            }
        }
    }
};

  console.log('Modified event response:', JSON.stringify(event.response, null, 2));
        
  return event;
};