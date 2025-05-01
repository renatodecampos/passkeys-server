import { WebAuthnCredential } from "@simplewebauthn/server";

export interface LoggedInUser {
    id: string;
    username: string;
    credentials: WebAuthnCredential[];
}