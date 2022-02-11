import {ensureAppStarted, hasClaim, verifyAppCheckContext, verifyAuthenticationContext} from "../../functions/lib";
import {CallableContext} from "firebase-functions/lib/providers/https";
import {assert, property, lorem} from "fast-check";
import * as admin from "firebase-admin";
import DecodedIdToken = admin.auth.DecodedIdToken;
import {PermissionLevel} from "@shsusac/subman2-common-api";

describe("ensureAppStarted", () => {
	it("Starts firebase SDK if it has not already been started", () => {
		const fetchAppSpy = jest.spyOn(admin, "app")
			.mockImplementation();
		const initAppSpy = jest.spyOn(admin, "initializeApp")
			.mockImplementation();

		ensureAppStarted();

		expect(fetchAppSpy).toBeCalledTimes(1);
		expect(initAppSpy).toBeCalledTimes(1);

		fetchAppSpy.mockRestore();
		initAppSpy.mockRestore();
	});

	it("Does not start firebase SDK if it has already been started", () => {
		const fetchAppSpy = jest.spyOn(admin, "app")
			.mockImplementation();
		const initAppSpy = jest.spyOn(admin, "initializeApp")
			.mockImplementation();

		ensureAppStarted();

		fetchAppSpy.mockReturnValue({} as admin.app.App);

		ensureAppStarted();

		expect(fetchAppSpy).toBeCalledTimes(2);
		expect(initAppSpy).toBeCalledTimes(1);

		fetchAppSpy.mockRestore();
		initAppSpy.mockRestore();
	});
})

const buildContext = (key: string, value?: string | null) =>
{
	const token = {

	} as DecodedIdToken;

	token[key] = value;

	return {
		auth: {
			token: token
		},
		app: {}
	} as CallableContext;
};

describe("verifyAuthenticationContext", () => {
	it("Rejects missing context", () => {
		expect(() => verifyAuthenticationContext({
			app: {}
		} as CallableContext, "test")).toThrowError("No_Auth_Context");
	})

	it("Rejects missing claim", () => {
		expect(() => verifyAuthenticationContext({
			auth: {
				token: {

				}
			},
			app: {}
		} as CallableContext, "test")).toThrowError("Permission_Level_Insufficient");
	});

	it("Rejects null claim value", () => {
		expect(() => verifyAuthenticationContext(buildContext("test", null), "test", "reader")).toThrowError("Permission_Level_Insufficient");
	});

	it("Rejects missing claim value", () => {
		assert(
			property(lorem({ maxCount: 1}), (name) => {
				const context = buildContext(name, undefined);
				expect(() => verifyAuthenticationContext(context, name, "reader")).toThrowError("Permission_Level_Insufficient");
			})
		);
	});

	it("Rejects invalid claim value", () => {
		assert(
			property(lorem({ maxCount: 1}), lorem({ maxCount: 1}), (name, value) => {
				const context = buildContext(name, undefined);
				expect(() => verifyAuthenticationContext(context, name, value as PermissionLevel)).toThrowError("Permission_Level_Insufficient");
			})
		);
	});

	it("Rejects too low claim value", () => {
		assert(
			property(lorem({ maxCount: 1}), (name) => {
				const context = buildContext(name, "reader");
				expect(() => verifyAuthenticationContext(context, name, "admin")).toThrowError("Permission_Level_Insufficient");
			})
		);
	});

	it("Accepts present claim", () => {
		assert(
			property(lorem({ maxCount: 1}), (name) => {
				const context = buildContext(name);
				expect(() => verifyAuthenticationContext(context, name)).not.toThrowError();
			})
		);
	});

	it("Accepts present claim value", () => {
		assert(
			property(lorem({ maxCount: 1}), (name) => {
				const context = buildContext(name, "reader");
				expect(() => verifyAuthenticationContext(context, name, "reader")).not.toThrowError();
			})
		);

		assert(
			property(lorem({ maxCount: 1}), (name) => {
				const context = buildContext(name, "writer");
				expect(() => verifyAuthenticationContext(context, name, "writer")).not.toThrowError();
			})
		);

		assert(
			property(lorem({ maxCount: 1}), (name) => {
				const context = buildContext(name, "admin");
				expect(() => verifyAuthenticationContext(context, name, "admin")).not.toThrowError();
			})
		);
	});

	it("Accepts higher claim value", () => {
		assert(
			property(lorem({ maxCount: 1}), (name) => {
				const context = buildContext(name, "admin");
				expect(() => verifyAuthenticationContext(context, name, "reader")).not.toThrowError();
			})
		);

		assert(
			property(lorem({ maxCount: 1}), (name) => {
				const context = buildContext(name, "admin");
				expect(() => verifyAuthenticationContext(context, name, "writer")).not.toThrowError();
			})
		);

		assert(
			property(lorem({ maxCount: 1}), (name) => {
				const context = buildContext(name, "admin");
				expect(() => verifyAuthenticationContext(context, name, "admin")).not.toThrowError();
			})
		);
	});
});

describe("verifyAppCheckContext", () => {
	it("Passes when an app check context is present", () => {
		expect(() => verifyAppCheckContext({
			rawRequest: {},
			app: {
				token: {},
				appId: "Test"
			}
		} as CallableContext)).not.toThrowError();
	});

	it("Throws when the context is missing", () => {
		expect(() => verifyAppCheckContext({
			rawRequest: {},
			app: undefined
		} as CallableContext)).toThrowError("No_AppCheck_Context")
	})
})

describe("hasClaims", () => {

	it("Rejects missing context", () => {
		const result = hasClaim({} as CallableContext, "test");
		expect(result).toBe(false);
	})

	it("Rejects missing claim", () => {
		const result = hasClaim({
			auth: {
				token: {

				}
			}
		} as CallableContext, "test");
		expect(result).toBe(false);
	});

	it("Rejects null claim value", () => {
		const result = hasClaim(buildContext("test", null), "test", "reader");
		expect(result).toBe(false);
	});

	it("Rejects missing claim value", () => {
		assert(
			property(lorem({ maxCount: 1}), (name) => {
				const context = buildContext(name, undefined);
				const result = hasClaim(context, name, "reader");
				expect(result).toBe(false);
			})
		);
	});

	it("Rejects invalid claim value", () => {
		assert(
			property(lorem({ maxCount: 1}), lorem({ maxCount: 1}), (name, value) => {
				const context = buildContext(name, undefined);
				const result = hasClaim(context, name, value as PermissionLevel);
				expect(result).toBe(false);
			})
		);
	});

	it("Rejects too low claim value", () => {
		assert(
			property(lorem({ maxCount: 1}), (name) => {
				const context = buildContext(name, "reader");
				const result = hasClaim(context, "admin");
				expect(result).toBe(false);
			})
		);
	});

	it("Accepts present claim", () => {
		assert(
			property(lorem({ maxCount: 1}), (name) => {
				const context = buildContext(name);
				const result = hasClaim(context, name);
				expect(result).toBe(true);
			})
		);
	});

	it("Accepts present claim value", () => {
		assert(
			property(lorem({ maxCount: 1}), (name) => {
				const context = buildContext(name, "reader");
				const result = hasClaim(context, name, "reader");
				expect(result).toBe(true);
			})
		);

		assert(
			property(lorem({ maxCount: 1}), (name) => {
				const context = buildContext(name, "writer");
				const result = hasClaim(context, name, "writer");
				expect(result).toBe(true);
			})
		);

		assert(
			property(lorem({ maxCount: 1}), (name) => {
				const context = buildContext(name, "admin");
				const result = hasClaim(context, name, "admin");
				expect(result).toBe(true);
			})
		);
	});

	it("Accepts higher claim value", () => {
		assert(
			property(lorem({ maxCount: 1}), (name) => {
				const context = buildContext(name, "admin");
				const result = hasClaim(context, name, "reader");
				expect(result).toBe(true);
			})
		);

		assert(
			property(lorem({ maxCount: 1}), (name) => {
				const context = buildContext(name, "admin");
				const result = hasClaim(context, name, "writer");
				expect(result).toBe(true);
			})
		);

		assert(
			property(lorem({ maxCount: 1}), (name) => {
				const context = buildContext(name, "admin");
				const result = hasClaim(context, name, "admin");
				expect(result).toBe(true);
			})
		);
	});
});