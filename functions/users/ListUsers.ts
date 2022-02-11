import {https} from "firebase-functions";
import {auth} from "firebase-admin";
import {ensureAppStarted, verifyAuthenticationContext} from "../lib";
import {UserPermissionsDTO} from "@shsusac/subman2-common-api";

ensureAppStarted();

export const ListUsers = https.onCall(async (data: undefined, context) => {

	verifyAuthenticationContext(context, "SystemRole", "reader");

	let userPage = await auth().listUsers();

	const userList: auth.UserRecord[] = [];

	if(!userPage.users) {
		return [];
	}

	while(userPage && userPage.pageToken) {
		userList.push(...userPage.users);
		userPage = await auth().listUsers(undefined, userPage.pageToken);
	}

	userList.push(...userPage.users);

	return userList.map<UserPermissionsDTO>(userRecord => {
		const dto: UserPermissionsDTO = {
			UID: userRecord.uid,
		};

		if (userRecord.customClaims?.EquipmentRole) {
			dto.Equipment = userRecord.customClaims.EquipmentRole;
		}

		if (userRecord.customClaims?.ChatRole) {
			dto.Chat = userRecord.customClaims.ChatRole;
		}

		if (userRecord.customClaims?.SystemRole) {
			dto.System = userRecord.customClaims.SystemRole;
		}

		if (userRecord.customClaims?.StorageRole) {
			dto.Storage = userRecord.customClaims.StorageRole;
		}

		if (userRecord.customClaims?.CalenderRole) {
			dto.Calender = userRecord.customClaims.CalenderRole;
		}

		return dto;
	});
})