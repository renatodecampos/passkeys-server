import { rpID, expectedOrigin } from "../setup"
import { getUser, updateUser } from "../infra/database/database";
import { AuthenticationResponseJSON, GenerateAuthenticationOptionsOpts, generateAuthenticationOptions, VerifiedAuthenticationResponse, verifyAuthenticationResponse, VerifyAuthenticationResponseOpts, WebAuthnCredential } from "@simplewebauthn/server";
import { redis } from "../infra/database/redis";
import { logger } from "../infra/logger";



export const getAuthenticationOptions = async (username: string) => {
    const user = await getUser(username);
    if (!user) {
        logger.error(`User ${username} not found`);
        throw new Error('User not found');
    }  

    const opts: GenerateAuthenticationOptionsOpts = {
        timeout: 60000,
        allowCredentials: user.credentials.map((cred) => ({
            id: cred.id,
            type: 'public-key',
            transports: cred.transports,
        })),
        userVerification: 'preferred',
        rpID,
    };

    const options = await generateAuthenticationOptions(opts);

    logger.debug(`Generating authentication options for user ${username}`);

    // Store challenge in Redis with 5-minute expiration
    await redis.setex(`challenge:${username}-authentication`, 300, options.challenge);

    logger.debug(`Authentication options generated for user ${username}`);

    return options;
}

export const verifyAuthentication = async (username: string, authenticationResponse: AuthenticationResponseJSON) => {
    const user = await getUser(username);
    if (!user) {
        logger.error(`User ${username} not found`);
        throw new Error('User not found');
    }

    logger.debug(`Verifying authentication ${JSON.stringify(authenticationResponse)}`);

    const expectedChallenge = await redis.get(`challenge:${username}-authentication`);

    if (!expectedChallenge) {
        logger.error(`No challenge found or challenge expired for user ${username}`);
        throw new Error('No challenge found or challenge expired');
    } else {
        logger.debug(`Expected challenge: ${expectedChallenge}`);
    }

    // Find existing credential by ID
    let dbCredential: WebAuthnCredential | undefined;
    // "Query the DB" here for a credential matching `cred.id`
    for (const cred of user.credentials) {
        if (cred.id === authenticationResponse.id) {
            dbCredential = cred;
            break;
        }
    }

    if (!dbCredential) {
        logger.error(`Authenticator is not registered with this site for user ${username}`);
        throw new Error('Authenticator is not registered with this site');
    }

    logger.debug(`DB credential: ${JSON.stringify(dbCredential)}`);

    logger.debug(`Verifying authentication for user ${username}`);

    let verification: VerifiedAuthenticationResponse;
    try {
        const opts: VerifyAuthenticationResponseOpts = {
            response: authenticationResponse,
            expectedChallenge: `${expectedChallenge}`,
            expectedOrigin: expectedOrigin,
            expectedRPID: rpID,
            credential: {
                id: dbCredential.id,
                publicKey: new Uint8Array(dbCredential.publicKey.buffer),
                counter: dbCredential.counter,
                transports: dbCredential.transports,
            },
            requireUserVerification: true,
        };
        
        logger.debug(`Verification opts: ${JSON.stringify(opts)}`);

        verification = await verifyAuthenticationResponse(opts);
        logger.debug(`Verification result: ${JSON.stringify(verification)}`);
    } catch (error) {
        const _error = error as Error;
        logger.error(`Error verifying authentication for user ${username}: ${_error.message}`);
        throw _error;
    }

    const { verified, authenticationInfo } = verification;

    if (verified && authenticationInfo && dbCredential) {
        logger.info(`Updating credential counter for user ${username}`);
        dbCredential.counter = authenticationInfo?.newCounter;
        await updateUser(user.id, { credentials: user.credentials });
        logger.info(`Authentication verified for user ${username}`);
    }

    return verification;
}
