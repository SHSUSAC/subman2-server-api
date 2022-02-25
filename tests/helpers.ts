import * as functions from "firebase-functions-test";
import * as admin from "firebase-admin";
import {get as httpGet} from "http";

export type SDKSettings = {
    testId?: string,
    offline: boolean,
    firestoreEmulatorLocation?: string
    authEmulatorLocation?: string
}

export function InitialiseSDK(settings: SDKSettings) {
    const projectId = settings?.testId ?? "Testing"

    process.env.GCLOUD_PROJECT = projectId;
    if(!settings.offline) {
        process.env.FIRESTORE_EMULATOR_HOST = settings.firestoreEmulatorLocation ?? "localhost:8080";
        process.env.FIREBASE_AUTH_EMULATOR_HOST = settings.authEmulatorLocation ?? "localhost:9099";
    }

    const testEnv = functions({ projectId });
    admin.initializeApp({ projectId });

    return testEnv;
}

export async function ClearUserAccounts(testId?: string, emulatorLocation?: string) {
    await httpGet(`http://${emulatorLocation ?? "localhost:9099"}/emulator/v1/projects/${testId ?? "testing"}/accounts`,{method: "DELETE"})
}