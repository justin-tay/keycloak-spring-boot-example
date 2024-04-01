const KEYCLOAK_ADMIN = process.env.KEYCLOAK_ADMIN ?? 'admin';
const KEYCLOAK_ADMIN_PASSWORD = process.env.KEYCLOAK_ADMIN_PASSWORD ?? 'admin';
const KEYCLOAK_SERVER = process.env.KEYCLOAK_SERVER ?? 'http://localhost:8080';
const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM ?? 'test';
const KEYCLOAK_CLIENT =
  process.env.KEYCLOAK_CLIENT ?? 'keycloak-spring-boot-example';

const credentials = async ({ server, user, password }) => {
  const response = await fetch(
    `${server}/realms/master/protocol/openid-connect/token`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        username: user,
        password,
        grant_type: 'password',
        client_id: 'admin-cli',
      }),
    }
  );
  const token = await response.json();
  if (token.error_description) {
    throw new Error(token.error_description);
  }
  return token.access_token;
};

const setup = async () => {
  const bearer = await credentials({
    server: KEYCLOAK_SERVER,
    user: KEYCLOAK_ADMIN,
    password: KEYCLOAK_ADMIN_PASSWORD,
  });
  const headers = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${bearer}`,
  };
  // Create realm
  console.info(`Creating realm '${KEYCLOAK_REALM}'`);
  let response = await fetch(`${KEYCLOAK_SERVER}/admin/realms`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      enabled: true,
      realm: KEYCLOAK_REALM,
      registrationAllowed: true,
    }),
  });
  let json = null;
  if (response.status !== 201) {
    json = await response.json();
    console.error(
      `Failed to create realm '${KEYCLOAK_REALM}': ${json.errorMessage}`
    );
  } else {
    console.info(`Created realm '${KEYCLOAK_REALM}'`);
  }
  // Create client
  console.info(`Creating client '${KEYCLOAK_CLIENT}'`);
  response = await fetch(
    `${KEYCLOAK_SERVER}/admin/realms/${KEYCLOAK_REALM}/clients`,
    {
      method: 'POST',
      headers,
      body: JSON.stringify({
        attributes: {
          'backchannel.logout.revoke.offline.tokens': 'false',
          'backchannel.logout.session.required': 'true',
          'backchannel.logout.url':
            'http://localhost:8081/logout/connect/back-channel/keycloak',
          'jwks.url': 'http://localhost:8081/oauth2/jwks',
          'post.logout.redirect.uris': 'http://localhost:8081/*',
          'use.jwks.url': 'true',
        },
        clientAuthenticatorType: 'client-jwt',
        clientId: KEYCLOAK_CLIENT,
        description: '',
        directAccessGrantsEnabled: false,
        frontchannelLogout: false,
        name: '',
        protocol: 'openid-connect',
        publicClient: false,
        redirectUris: ['http://localhost:8081/*'],
        rootUrl: '',
        serviceAccountsEnabled: false,
        standardFlowEnabled: true,
        webOrigins: ['http://localhost:8081/*'],
      }),
    }
  );
  if (response.status !== 201) {
    json = await response.json();
    console.error(
      `Failed to create client '${KEYCLOAK_CLIENT}': ${json.errorMessage}`
    );
  } else {
    console.info(`Created client '${KEYCLOAK_CLIENT}'`);
  }
};

setup()
  .catch((err) => console.error(err.message ?? err))
  .finally(() => console.info('Setup complete'));
