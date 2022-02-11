import * as initTestSdk from "firebase-functions-test";
import * as admin from "firebase-admin";
import {HttpsFunction, Runnable} from "firebase-functions/lib/cloud-functions";
import {asciiString, assert, constantFrom, property, asyncProperty, context} from "fast-check";
import {permissionLevelSchema, UserPermissionsDTO} from "@shsusac/subman2-common-api";
import {ZodFastCheck} from "zod-fast-check";

const functionsTestSdk = initTestSdk();

let adminInitStub: jest.SpyInstance<admin.app.App, [options?: admin.AppOptions, name?: string]>,
    appFetchStub: jest.SpyInstance<admin.app.App, [name?: string]>,
	functionIndex: {
		users: {
			UpdateUserPermissions: HttpsFunction & Runnable<any>;
		}
	};

beforeAll(async () => {
	// [START stubAdminInit]
	// If index.js calls admin.initializeApp at the top of the file,
	// we need to stub it out before requiring index.js. This is because the
	// functions will be executed as a part of the import process.
	// Here we stub admin.initializeApp to be a dummy function that doesn't do anything.
	adminInitStub = jest.spyOn(admin, 'initializeApp')
		.mockImplementation();
	appFetchStub = jest.spyOn(admin, "app")
		.mockImplementation()
		.mockReturnValue({} as admin.app.App);
	// adminInitStub = stub(admin, 'initializeApp');
	// Now we can require index.js and save the exports inside a namespace called functionIndex.
	functionIndex = require("../../../functions/index");
	// [END stubAdminInit]

});


it("Rejects missing app check token", () => {
	const result = functionIndex.users.UpdateUserPermissions.run(undefined, {});
	expect(result).rejects.toThrowError("No_AppCheck_Context");
});

it("Rejects missing authentication", async () => {
	const result = functionIndex.users.UpdateUserPermissions.run(undefined, {
		app: {
		}
	});
	await expect(result).rejects.toThrowError("No_Auth_Context");
});

it("Rejects insufficient authentication", async () => {
	const result = functionIndex.users.UpdateUserPermissions.run(undefined, {
		app: {
		},
		auth: {
			token: {
				SystemRole: "reader"
			}
		}
	});
	await expect(result).rejects.toThrowError("Permission_Level_Insufficient");
});

it("Rejects missing DTOs", async () => {
	const result = functionIndex.users.UpdateUserPermissions.run(undefined, {
		app: {
		},
		auth: {
			token: {
				SystemRole: "admin"
			}
		}
	});
	await expect(result).rejects.toThrowError("DTO_Validation_Failed");
});

it("Rejects invalid DTOs", () => {
	assert(
		property(asciiString(), asciiString(), (id, permissionLevel) => {
			const permissionDto = {
				UID: id,
				Equipment: permissionLevel
			}

			const result = functionIndex.users.UpdateUserPermissions.run(permissionDto, {
				app: {
				},
				auth: {
					token: {
						SystemRole: "admin"
					}
				}
			});
			expect(result).rejects.toThrowError("DTO_Validation_Failed");
		})
	);
});

it("Successfully edits a users permission", async () => {
	const permissionLevelArbitrary = ZodFastCheck().inputOf(permissionLevelSchema);
	const roleArbitrary = constantFrom<"Equipment" | "Calender" | "Chat" | "System" | "Storage">("Equipment", "Calender", "Chat", "System", "Storage");
	await assert(
		asyncProperty(permissionLevelArbitrary, roleArbitrary, context(), async (newLevel, role, ctx) => {
			let authMock: jest.SpyInstance<admin.auth.Auth, [app?: admin.app.App]> | null = null;
			try {
				const user = functionsTestSdk.auth.exampleUserRecord();

				const dto: UserPermissionsDTO = {
					UID: user.uid
				};
				dto[role] = newLevel;

				jest.mock('firebase-admin');

				authMock = jest.spyOn(admin, "auth")
					.mockImplementation(() => (
						{
							setCustomUserClaims: async (uid: string, incomingClaimsToSet: Record<string, string>) => {
								expect(uid).toBe(user.uid);
								const roleName = role + "Role";
								expect(incomingClaimsToSet[roleName]).toBe(newLevel);
							}
						} as admin.auth.Auth
					));

				ctx.log(JSON.stringify(dto));

				await functionIndex.users.UpdateUserPermissions.run(dto,
					{
						app: {},
						auth: {
							token: {
								SystemRole: "admin"
							}
						}
					});
			}
			finally {
				authMock?.mockRestore();
				jest.unmock("firebase-admin");
			}
		})
	)
})

afterAll(() => {
	adminInitStub.mockRestore();
	appFetchStub.mockRestore();
	functionsTestSdk.cleanup();
});