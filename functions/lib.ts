import {
  CallableContext,
  HttpsError,
} from "firebase-functions/lib/providers/https";
import {PermissionLevel, permissionLevelSchema} from "@shsusac/subman2-common-api";
import {https} from "firebase-functions";
import {app, initializeApp} from "firebase-admin";

export function ensureAppStarted(): void {
  if(!app()){
    initializeApp();
  }
}

export function verifyAuthenticationContext(context: CallableContext, name: string, value?: PermissionLevel): void {
  verifyAppCheckContext(context);

  if(!context.auth) {
    throw new https.HttpsError("unauthenticated", "No_Auth_Context");
  }

  if(!hasClaim(context, name, value)) {
    throw new https.HttpsError("permission-denied", "Permission_Level_Insufficient")
  }
}

/**
 * Checks the app check token in the function context
 * and throws if it is invalid
 * @param {CallableContext} context The context from the function execution
 */
export function verifyAppCheckContext(context: CallableContext): void {
  // context.app will be undefined if the request doesn't include an
  // App Check token. (If the request includes an invalid App Check
  // token, the request will be rejected with HTTP error 401.)
  if (context.app == undefined) {
    throw new HttpsError(
        "failed-precondition",
        "No_AppCheck_Context");
  }
}

/**
 * Checks for a claim in the auth token and checks if it has a provided value
 * @param {CallableContext} context The context from the function execution
 * @param {String} name The name of the claim to find in the token
 * @param {String} value The value to check for in the claim, can be optional in which case only the existence of the claim is checked
 */
export function hasClaim(context: CallableContext, name: string, value?: PermissionLevel): boolean {

  const entry = context.auth?.token[name] as string;

  if(!context.auth?.token){
    return false;
  }

  if(!context.auth.token.hasOwnProperty(name)){
    return false;
  }

  if(value){
    //Has claim, we now check the value
    const claimLevelResult = permissionLevelSchema.safeParse(entry);
    if(!claimLevelResult.success) {
      return false;
    }
    const claimLevel = claimLevelResult.data;

    if(claimLevel === null) {
      return false;
    }

    const hasAdmin = claimLevel === "admin";
    const hasWriter = claimLevel === "writer";
    const hasReader = claimLevel === "reader";

    let hasPermission = false;

    if (value === "admin") {
      hasPermission = hasAdmin;
    }
    if (value === "writer") {
      hasPermission = hasAdmin || hasWriter;
    }
    if (value === "reader") {
      hasPermission = hasAdmin || hasWriter || hasReader;
    }
    return hasPermission;
  }
  else {
    //Has claim and we are not checking for a value
    return true;
  }
}
