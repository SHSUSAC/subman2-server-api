import {https} from "firebase-functions";
import * as admin from "firebase-admin";
import { verifyAuthenticationContext} from "../lib";
import {EssentialUserInformation} from "@shsusac/subman2-common-api";


export const ListUsers = https.onCall(async (data: undefined, context) => {

	verifyAuthenticationContext(context, "SystemRole", "reader");

	let userPage = await admin.auth().listUsers();

	const userList: admin.auth.UserRecord[] = [];

	if(!userPage.users) {
		return [];
	}

	while(userPage && userPage.pageToken) {
		userList.push(...userPage.users);
		userPage = await admin.auth().listUsers(undefined, userPage.pageToken);
	}

	userList.push(...userPage.users);

	return userList.map<EssentialUserInformation>(userRecord => {
		const dto: EssentialUserInformation = {
			UID: userRecord.uid,
			DisplayName: userRecord.displayName ?? (userRecord.email ?? userRecord.uid)
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