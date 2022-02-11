import {https} from "firebase-functions";
import {auth} from "firebase-admin";
import {ensureAppStarted, verifyAuthenticationContext} from "../lib";
import {PermissionLevel, UserPermissionsDTO, userPermissionsDTOSchema} from "@shsusac/subman2-common-api";
import {ZodError} from "zod";

ensureAppStarted();

export const UpdateUserPermissions = https.onCall(async (data, context) => {

	verifyAuthenticationContext(context, "SystemRole", "admin");

	const result:
		{ success: true; data: UserPermissionsDTO; } |
		{ success: false; error: ZodError<UserPermissionsDTO>; }
		= await userPermissionsDTOSchema.safeParseAsync(data)

	if (!result.success) {
		// handle error then return
		throw new https.HttpsError("invalid-argument", "DTO_Validation_Failed", {
			zodErrors: result.error.errors
		})
	}

	const userPermissionsDTO = result.data;
	const userClaims: {
		EquipmentRole?: PermissionLevel,
		ChatRole?: PermissionLevel,
		SystemRole?: PermissionLevel,
		StorageRole?: PermissionLevel,
		CalenderRole?: PermissionLevel,
	} = {};

	if (userPermissionsDTO.Equipment !== undefined) {
		userClaims.EquipmentRole = userPermissionsDTO.Equipment
	}

	if (userPermissionsDTO.Chat !== undefined) {
		userClaims.ChatRole = userPermissionsDTO.Chat
	}

	if (userPermissionsDTO.System !== undefined) {
		userClaims.SystemRole = userPermissionsDTO.System
	}

	if (userPermissionsDTO.Storage !== undefined) {
		userClaims.StorageRole = userPermissionsDTO.Storage
	}

	if (userPermissionsDTO.Calender !== undefined) {
		userClaims.CalenderRole = userPermissionsDTO.Calender
	}

	await auth().setCustomUserClaims(data.UID, userClaims);
	return;
});