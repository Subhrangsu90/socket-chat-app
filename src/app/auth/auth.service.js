import "dotenv/config";
import crypto from "node:crypto";

const AUTH_COOKIE_NAME = "chat_auth_token";
const STATE_COOKIE_NAME = "chat_auth_state";
const COOKIE_MAX_AGE_SECONDS = 60 * 60;
let discoveryCache;

function getIssuer() {
	return (
		process.env.OIDC_ISSUER || "https://autho.brewcodex.online"
	).replace(/\/$/, "");
}

function getBaseUrl(req) {
	if (process.env.BASE_URL) {
		return process.env.BASE_URL.replace(/\/$/, "");
	}

	return `${req.protocol}://${req.get("host")}`;
}

function getRedirectUri(req) {
	if (process.env.REDIRECT_URI) {
		return process.env.REDIRECT_URI.replace(/\/$/, "");
	}

	return `${getBaseUrl(req)}/auth/callback`;
}

function shouldUseSecureCookies(req) {
	if (typeof process.env.COOKIE_SECURE === "string") {
		return process.env.COOKIE_SECURE === "true";
	}

	const forwardedProto = req.get("x-forwarded-proto");
	return req.secure || forwardedProto === "https";
}

function serializeCookie(name, value, options = {}) {
	const parts = [`${name}=${encodeURIComponent(value)}`];
	if (options.maxAge) parts.push(`Max-Age=${options.maxAge}`);
	if (options.httpOnly) parts.push("HttpOnly");
	if (options.secure) parts.push("Secure");
	// Always set SameSite=Lax for auth cookies
	parts.push("SameSite=Lax");
	parts.push(`Path=${options.path || "/"}`);
	return parts.join("; ");
}

function parseCookies(req) {
	const header = req.headers.cookie;
	if (!header) return {};

	return header.split(";").reduce((cookies, pair) => {
		const [rawName, ...rawValue] = pair.trim().split("=");
		if (!rawName) return cookies;

		cookies[rawName] = decodeURIComponent(rawValue.join("="));
		return cookies;
	}, {});
}

function setCookie(res, req, name, value, maxAge = COOKIE_MAX_AGE_SECONDS) {
	res.append(
		"Set-Cookie",
		serializeCookie(name, value, {
			httpOnly: true,
			secure: shouldUseSecureCookies(req),
			maxAge,
		}),
	);
}

function clearCookie(res, req, name) {
	res.clearCookie(name, {
		httpOnly: true,
		secure: shouldUseSecureCookies(req),
		sameSite: "Lax",
		path: "/",
	});
	// res.append(
	// 	"Set-Cookie",
	// 	serializeCookie(name, "", {
	// 		httpOnly: true,
	// 		secure: shouldUseSecureCookies(req),
	// 		maxAge: 0,
	// 	}),
	// );
}

function getStateToken(req) {
	const cookies = parseCookies(req);
	return cookies[STATE_COOKIE_NAME];
}

function getAuthToken(req) {
	return parseCookies(req)[AUTH_COOKIE_NAME];
}

function createLoginUrl(req) {
	const state = crypto.randomBytes(24).toString("base64url");
	const loginUrl = new URL("/auth/authenticate", getIssuer());

	loginUrl.searchParams.set("response_type", "code");
	loginUrl.searchParams.set("client_id", process.env.OIDC_CLIENT_ID);
	loginUrl.searchParams.set("redirect_uri", getRedirectUri(req));
	loginUrl.searchParams.set("scope", "openid profile email");
	loginUrl.searchParams.set("state", state);

	return { loginUrl, state };
}

function createRegisterUrl(req) {
	const state = crypto.randomBytes(24).toString("base64url");
	const registerUrl = new URL("/sign-up", getIssuer());

	registerUrl.searchParams.set("response_type", "code");
	registerUrl.searchParams.set("client_id", process.env.OIDC_CLIENT_ID);
	registerUrl.searchParams.set("redirect_uri", getRedirectUri(req));
	registerUrl.searchParams.set("scope", "openid profile email");
	registerUrl.searchParams.set("state", state);

	return { registerUrl, state };
}

async function getDiscoveryMetadata() {
	if (discoveryCache) return discoveryCache;

	const response = await fetch(
		`${getIssuer()}/.well-known/openid-configuration`,
	);
	const metadata = await response.json().catch(() => ({}));

	if (!response.ok) {
		throw new Error("Unable to load OIDC discovery metadata.");
	}

	discoveryCache = metadata;
	return discoveryCache;
}

async function exchangeCodeForToken(req, code) {
	const metadata = await getDiscoveryMetadata();
	const tokenEndpoint =
		metadata.token_endpoint || `${getIssuer()}/auth/token`;

	const response = await fetch(tokenEndpoint, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
		},
		body: JSON.stringify({
			grant_type: "authorization_code",
			code,
			redirect_uri: getRedirectUri(req),
			client_id: process.env.OIDC_CLIENT_ID,
			client_secret: process.env.OIDC_CLIENT_SECRET,
		}),
	});

	const data = await response.json().catch(() => ({}));

	if (!response.ok) {
		throw new Error(data.message || "Token exchange failed.");
	}

	return data;
}

async function fetchCurrentUser(req) {
	const token = getAuthToken(req);
	if (!token) return null;

	const metadata = await getDiscoveryMetadata();
	const userinfoEndpoint =
		metadata.userinfo_endpoint || `${getIssuer()}/user/userinfo`;

	const response = await fetch(userinfoEndpoint, {
		headers: {
			Authorization: `Bearer ${token}`,
		},
	});

	if (response.status === 401) return null;

	const data = await response.json().catch(() => ({}));

	if (!response.ok) {
		throw new Error(data.message || "Unable to load current user.");
	}

	return data;
}

async function revokeToken(req) {
	const token = getAuthToken(req);
	if (!token) return;

	await fetch(`${getIssuer()}/oauth/revoke`, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
		},
		body: JSON.stringify({
			token,
			token_type_hint: "refresh_token",
			client_id: process.env.OIDC_CLIENT_ID,
			client_secret: process.env.OIDC_CLIENT_SECRET,
		}),
	}).catch(() => {});
}

export {
	AUTH_COOKIE_NAME,
	STATE_COOKIE_NAME,
	clearCookie,
	createLoginUrl,
	createRegisterUrl,
	exchangeCodeForToken,
	fetchCurrentUser,
	getDiscoveryMetadata,
	getAuthToken,
	getStateToken,
	parseCookies,
	revokeToken,
	setCookie,
};
