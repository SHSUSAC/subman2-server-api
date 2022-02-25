import * as admin from "firebase-admin";
import {HttpsFunction, Runnable} from "firebase-functions/lib/cloud-functions";
import {array, assert, asyncProperty, constantFrom, context, nat, tuple, uuid} from "fast-check";
import {ZodFastCheck} from "zod-fast-check";
import {permissionLevelSchema, EssentialUserInformation} from "@shsusac/subman2-common-api";
import {ClearUserAccounts, InitialiseSDK} from "../../helpers";
import { FeaturesList } from "firebase-functions-test/lib/features";

let functionsTestSdk: FeaturesList;

let adminInitStub: jest.SpyInstance<admin.app.App, [options?: admin.AppOptions, name?: string]>,
	appFetchStub: jest.SpyInstance<admin.app.App, [name?: string]>,
	functionIndex: {
		users: {
			ListUsers: HttpsFunction & Runnable<any>;
		}
	};

describe("Online Emulated Tests", () => {
	jest.setTimeout(8000);
	beforeEach(async () => {

		functionsTestSdk = InitialiseSDK({
			offline: false,
			testId: "ListUsers"
		})

		adminInitStub = jest.spyOn(admin, 'initializeApp')
			.mockImplementation();

		functionIndex = await import("../../../functions/index");
	});

	it("Supplies expected user list", async () => {
		const permissionLevelArbitrary = ZodFastCheck().inputOf(permissionLevelSchema);
		const roleArbitrary = constantFrom<"Equipment" | "Calender" | "Chat" | "System" | "Storage">("Equipment", "Calender", "Chat", "System", "Storage");
		let iteration = 0;
		await assert(
			asyncProperty(array(tuple(permissionLevelArbitrary, roleArbitrary, uuid()), {minLength: 0}), context(), async (preExistingUserConfiguration, ctx) => {
				ctx.log("Iteration: "+ iteration);
				iteration++;
					for (let [permissionLevel, role, uid] of preExistingUserConfiguration) {
						const claims: {[p: string]: any} = {};
						claims[(role + "Role")] = permissionLevel;
						await admin.auth().createUser({
							uid: uid,
							displayName: uid
						});
						await admin.auth().setCustomUserClaims(uid, claims);
					}

					const result = (await functionIndex.users.ListUsers.run(undefined, {
						app: {},
						auth: {
							token: {
								SystemRole: "admin"
							}
						}
					})) as EssentialUserInformation[];

					const adminUserList: admin.auth.UserRecord[] = [];
					const listAllUsers = async (nextPageToken?: string) => {
						// List batch of users, 1000 at a time.
						const listUsersResult = await admin.auth().listUsers(1000, nextPageToken)
						adminUserList.push(...listUsersResult.users)
						if (listUsersResult.pageToken) {
							// List next batch of users.
							await listAllUsers(listUsersResult.pageToken);
						}
					}
					await listAllUsers();

					expect(result.length).toBe(adminUserList.length);
					if(result.length > 0) {
						if(result[0].Storage) {
							expect(result[0].Storage).toBe(adminUserList[0].customClaims?.StorageRole);
						}
						if(result[(result.length - 1)].Equipment) {
							expect(result[(result.length - 1)].Equipment).toBe(adminUserList[(adminUserList.length - 1)].customClaims?.EquipmentRole);
						}
					}
			})
		)
	});

	afterEach(() => {
		adminInitStub.mockRestore();
		functionsTestSdk.cleanup();
		ClearUserAccounts("ListUsers");
		admin.app().delete()
	});
});

describe("Offline Tests", () => {
	beforeEach(async () => {

		functionsTestSdk = InitialiseSDK({
			offline: true
		})

		adminInitStub = jest.spyOn(admin, 'initializeApp')
			.mockImplementation();

		appFetchStub = jest.spyOn(admin, "app")
			.mockImplementation()
			.mockReturnValue({} as admin.app.App);
		functionIndex = await import("../../../functions/index");
	});

	it("Rejects missing app check token", () => {
		const result = functionIndex.users.ListUsers.run(undefined, {});
		expect(result).rejects.toThrowError("No_AppCheck_Context");
	});

	it("Rejects missing authentication", async () => {
		const result = functionIndex.users.ListUsers.run(undefined, {
			app: {
			}
		});
		await expect(result).rejects.toThrowError("No_Auth_Context");
	});

	it("Supplies expected user chunks", async () => {
		const permissionLevelArbitrary = ZodFastCheck().inputOf(permissionLevelSchema);
		const roleArbitrary = constantFrom<"Equipment" | "Calender" | "Chat" | "System" | "Storage">("Equipment", "Calender", "Chat", "System", "Storage");
		await assert(
			asyncProperty(array(tuple(permissionLevelArbitrary, roleArbitrary), {minLength: 0}), nat(50), async (preExistingUserConfiguration, perChunk) => {
				let authMock: jest.SpyInstance<admin.auth.Auth, [app?: admin.app.App]> | null = null;
				try {
					const savedUsers: admin.auth.UserRecord[] = [];
					preExistingUserConfiguration.forEach(([permissionLevel, role]) => {
						const newUser = functionsTestSdk.auth.exampleUserRecord();
						const claims: {[p: string]: any} = {};
						claims[(role + "Role")] = permissionLevel;
						newUser.customClaims = claims;
						savedUsers.push(newUser)
					});

					const chunkedUsers = savedUsers.reduce((resultArray: admin.auth.UserRecord[][], item, index) => {
						const chunkIndex = Math.floor(index / perChunk)

						if (!resultArray[chunkIndex]) {
							resultArray[chunkIndex] = [] // start a new chunk
						}

						resultArray[chunkIndex].push(item)

						return resultArray
					}, []);

					authMock = jest.spyOn(admin, "auth")
						.mockImplementation(() => (
							{
								async listUsers(maxResults?: number, pageToken?: string): Promise<admin.auth.ListUsersResult> {
									if(pageToken) {
										const index: number = Number(pageToken);
										const data: admin.auth.ListUsersResult = {
											users: chunkedUsers[index]
										}
										if(index === (chunkedUsers.length - 1)){
											return data;
										}
										else {
											data.pageToken = (index + 1).toString();
											return data;
										}
									}
									else {
										const data: admin.auth.ListUsersResult = {
											users: chunkedUsers[0],
										};
										if(chunkedUsers.length === 1) {
											return data;
										}
										else {
											data.pageToken = (1).toString();
											return data;
										}
									}
								}
							} as admin.auth.Auth
						));
					const result = (await functionIndex.users.ListUsers.run(undefined, {
						app: {},
						auth: {
							token: {
								SystemRole: "admin"
							}
						}
					})) as EssentialUserInformation[];

					let resultCounter = 0;
					for (let userPermissionsDTO of result) {
						expect(userPermissionsDTO.UID).toBe(savedUsers[resultCounter].uid);

						if (savedUsers[resultCounter].customClaims?.EquipmentRole) {
							expect(userPermissionsDTO.Equipment).toBe(savedUsers[resultCounter].customClaims?.EquipmentRole);
						}

						if (savedUsers[resultCounter].customClaims?.ChatRole) {
							expect(userPermissionsDTO.Chat).toBe(savedUsers[resultCounter].customClaims?.ChatRole);
						}

						if (savedUsers[resultCounter].customClaims?.StorageRole) {
							expect(userPermissionsDTO.Storage).toBe(savedUsers[resultCounter].customClaims?.StorageRole);
						}

						if (savedUsers[resultCounter].customClaims?.CalenderRole) {
							expect(userPermissionsDTO.Calender).toBe(savedUsers[resultCounter].customClaims?.CalenderRole);
						}

						if (savedUsers[resultCounter].customClaims?.SystemRole) {
							expect(userPermissionsDTO.System).toBe(savedUsers[resultCounter].customClaims?.SystemRole);
						}

						resultCounter++;
					}
				}
				finally {
					authMock?.mockRestore();
				}
			})
		)
	});

	afterEach(() => {
		adminInitStub.mockRestore();
		appFetchStub.mockRestore();
		functionsTestSdk.cleanup();
		admin.app().delete()
	});
});