import { generateRegistrationOptions, GenerateRegistrationOptionsOpts, RegistrationResponseJSON, verifyRegistrationResponse, WebAuthnCredential } from "@simplewebauthn/server";
import { rpID, rpName, expectedOrigin, registrationTimeout } from "../setup"
import { createUser, getUser, updateUser } from "../infra/database/database";
import { v4 as uuidv4 } from 'uuid';
import { redis } from "../infra/database/redis";
import { logger } from "../infra/logger";
/**
 * Get Registration Options
 * @param username - The username of the logged in user
 * @returns The registration options for the user
 */
export const getRegistrationOptions = async (username: string) => {
    let user = await getUser(username);
    if (!user) {
        logger.info(`Creating user ${username}`);
        await createUser({
            id: uuidv4(),
            username: username,
            credentials: [],
            displayName: username,
        });
        user = await getUser(username);
        logger.info(`User ${username} created`);
    }

    const options: GenerateRegistrationOptionsOpts = {
        rpName,
        rpID,
        userName: username,
        userID: new TextEncoder().encode(user?.id),
        userDisplayName: user?.displayName,
        timeout: Number(registrationTimeout) || 60000,
        attestationType: 'none',
        excludeCredentials: user!.credentials.map((cred) => ({
            id: cred.id,
            type: 'public-key',
            transports: cred.transports,
        })),
        authenticatorSelection: {
            residentKey: 'discouraged',
            userVerification: 'preferred',
        },
        supportedAlgorithmIDs: [-7, -257],
    };

    logger.debug(`Generating registration options for user ${username}`);

    const registrationOptions = await generateRegistrationOptions(options);

    logger.info(`Registration options generated for user ${username}`);

    // Store challenge in Redis with 5-minute expiration
    await redis.setex(`challenge:${username}-registration`, 300, registrationOptions.challenge);

    logger.debug(`Challenge stored in Redis for user ${username}`);

    return registrationOptions;
};


/**
 * Verify Registration
 * @param username - The username of the logged in user
 * @param registrationResponse - The registration response
 * @returns The verified registration response
 */
export const verifyRegistration = async (username: string, registrationResponse: RegistrationResponseJSON) => {
    const user = await getUser(username);
    if (!user) {
        logger.error(`User ${username} not found`);
        throw new Error('User not found');
    }

    logger.debug(`Verifying registration for user ${username}`);

    const expectedChallenge = await redis.get(`challenge:${username}-registration`);
    logger.debug(`Expected challenge: ${expectedChallenge}`);
    if (!expectedChallenge) {
        logger.error(`No challenge found or challenge expired for user ${username}`);
        throw new Error('No challenge found or challenge expired');
    }

    logger.debug(`Registration response: ${JSON.stringify(registrationResponse)}`);

    try {
        const verification = await verifyRegistrationResponse({
            response: registrationResponse,
            expectedChallenge: `${expectedChallenge}`,
            expectedOrigin: expectedOrigin,
            expectedRPID: rpID,
            requireUserVerification: false,
        });

        const { verified, registrationInfo } = verification;
        logger.debug(`Verification result: ${JSON.stringify(verification)}`);
        if (verified && registrationInfo?.credential) {
            // Update the credential's counter in the DB to the newest count in the authentication
            const { credential } = registrationInfo;
            credential.counter = registrationInfo.credential.counter;

            const existingCredential = user.credentials.find((cred) => cred.id === credential.id);

            if (!existingCredential) {
                logger.info(`Adding credential to user ${user.username}`);
                const newCredential: WebAuthnCredential = {
                    id: credential.id,
                    publicKey: credential.publicKey,
                    counter: credential.counter,
                    transports: registrationResponse.response.transports,
                };
                user.credentials.push(newCredential);
                await updateUser(user.id, { credentials: user.credentials });
                logger.info(`Credential added to user ${user.username}`);
            }
        }

        return verified;
    } catch (error) {
        const _error = error as Error;
        console.error(_error);
        throw _error;
    }
};
