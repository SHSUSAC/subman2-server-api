import * as initTestSdk from "firebase-functions-test";
import * as admin from "firebase-admin";
import {HttpsFunction, Runnable} from "firebase-functions/lib/cloud-functions";
import {array, assert, asyncProperty, constantFrom, nat, tuple} from "fast-check";
import {ZodFastCheck} from "zod-fast-check";
import {permissionLevelSchema, UserPermissionsDTO} from "@shsusac/subman2-common-api";

const functionsTestSdk = initTestSdk();

let adminInitStub: jest.SpyInstance<admin.app.App, [options?: admin.AppOptions, name?: string]>,
	appFetchStub: jest.SpyInstance<admin.app.App, [name?: string]>,
	functionIndex: {
		users: {
			ListUsers: HttpsFunction & Runnable<any>;
		}
	};

beforeAll(async () => {
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
				})) as UserPermissionsDTO[];

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

afterAll(() => {
	adminInitStub.mockRestore();
	appFetchStub.mockRestore();
	functionsTestSdk.cleanup();
});