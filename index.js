import http from "node:http";
import crypto from "node:crypto";
import { Server } from "socket.io";
import path from "node:path";
import express from "express";

const oidcConfig = {
	issuer: process.env.OIDC_ISSUER || "https://autho.brewcodex.online/",
	clientId: process.env.OIDC_CLIENT_ID,
	clientSecret: process.env.OIDC_CLIENT_SECRET,
	baseUrl: process.env.BASE_URL || "http://localhost:9000",
	sessionSecret: process.env.SESSION_SECRET || "dev-session-secret-change-me",
};

const cookieName = "chai_chat_sid";
const sessions = new Map();
let discoveryCache;
let jwksCache;

function base64Url(input) {
	return Buffer.from(input)
		.toString("base64")
		.replaceAll("+", "-")
		.replaceAll("/", "_")
		.replaceAll("=", "");
}

function randomToken(bytes = 32) {
	return base64Url(crypto.randomBytes(bytes));
}

function sha256(value) {
	return crypto.createHash("sha256").update(value).digest();
}

function timingSafeEqual(a, b) {
	const left = Buffer.from(a);
	const right = Buffer.from(b);
	return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function sign(value) {
	return base64Url(
		crypto.createHmac("sha256", oidcConfig.sessionSecret).update(value).digest(),
	);
}

function serializeSessionId(sessionId) {
	return `${sessionId}.${sign(sessionId)}`;
}

function parseCookies(cookieHeader = "") {
	return Object.fromEntries(
		cookieHeader
			.split(";")
			.map((cookie) => cookie.trim())
			.filter(Boolean)
			.map((cookie) => {
				const index = cookie.indexOf("=");
				if (index === -1) return [cookie, ""];
				return [
					decodeURIComponent(cookie.slice(0, index)),
					decodeURIComponent(cookie.slice(index + 1)),
				];
			}),
	);
}

function getSessionId(req) {
	const value = parseCookies(req.headers.cookie)[cookieName];
	if (!value) return null;
	const [sessionId, signature] = value.split(".");
	if (!sessionId || !signature || !timingSafeEqual(signature, sign(sessionId))) {
		return null;
	}
	return sessionId;
}

function getSession(req) {
	const sessionId = getSessionId(req);
	return sessionId ? sessions.get(sessionId) : null;
}

function setSessionCookie(res, sessionId) {
	const secure = oidcConfig.baseUrl.startsWith("https://");
	res.cookie(cookieName, serializeSessionId(sessionId), {
		httpOnly: true,
		sameSite: "lax",
		secure,
		path: "/",
		maxAge: 1000 * 60 * 60 * 24,
	});
}

function clearSessionCookie(res) {
	res.clearCookie(cookieName, { path: "/" });
}

function requireOidcEnv(res) {
	if (oidcConfig.clientId) return true;
	res.status(500).send(
		"OIDC_CLIENT_ID is required. Set OIDC_CLIENT_SECRET too if your OIDC app is confidential.",
	);
	return false;
}

async function discoverOidc() {
	if (discoveryCache) return discoveryCache;
	const issuer = oidcConfig.issuer.endsWith("/")
		? oidcConfig.issuer
		: `${oidcConfig.issuer}/`;
	const response = await fetch(`${issuer}.well-known/openid-configuration`);
	if (!response.ok) {
		throw new Error(`OIDC discovery failed with ${response.status}`);
	}
	discoveryCache = await response.json();
	return discoveryCache;
}

async function getJwks(jwksUri) {
	if (jwksCache) return jwksCache;
	const response = await fetch(jwksUri);
	if (!response.ok) {
		throw new Error(`OIDC JWKS fetch failed with ${response.status}`);
	}
	jwksCache = await response.json();
	return jwksCache;
}

function decodeJwtPart(part) {
	return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

async function verifyIdToken(idToken, nonce, metadata) {
	const [headerPart, payloadPart, signaturePart] = idToken.split(".");
	if (!headerPart || !payloadPart || !signaturePart) {
		throw new Error("Invalid id_token format");
	}

	const header = decodeJwtPart(headerPart);
	const payload = decodeJwtPart(payloadPart);
	const jwks = await getJwks(metadata.jwks_uri);
	const jwk = jwks.keys?.find((key) => key.kid === header.kid);
	if (!jwk) throw new Error("No matching JWKS key for id_token");

	const verifier = crypto.createVerify("RSA-SHA256");
	verifier.update(`${headerPart}.${payloadPart}`);
	verifier.end();
	const valid = verifier.verify(
		crypto.createPublicKey({ key: jwk, format: "jwk" }),
		Buffer.from(signaturePart, "base64url"),
	);
	if (!valid) throw new Error("Invalid id_token signature");

	const now = Math.floor(Date.now() / 1000);
	if (payload.iss !== metadata.issuer) throw new Error("Invalid id_token issuer");
	if (payload.exp <= now) throw new Error("Expired id_token");
	if (payload.nonce !== nonce) throw new Error("Invalid id_token nonce");

	const audience = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
	if (!audience.includes(oidcConfig.clientId)) {
		throw new Error("Invalid id_token audience");
	}

	return payload;
}

function userFromClaims(claims) {
	const name =
		claims.name ||
		claims.preferred_username ||
		claims.nickname ||
		claims.email ||
		"Authenticated user";

	return {
		id: claims.sub,
		name: String(name).trim().slice(0, 40),
		email: claims.email,
		picture: claims.picture,
	};
}

async function main() {
	const app = express();
	app.set("trust proxy", 1);

	app.get("/auth/login", async (req, res, next) => {
		try {
			if (!requireOidcEnv(res)) return;
			const metadata = await discoverOidc();
			const sessionId = randomToken();
			const state = randomToken();
			const nonce = randomToken();
			const codeVerifier = randomToken(48);
			const session = {
				state,
				nonce,
				codeVerifier,
				user: null,
			};
			sessions.set(sessionId, session);
			setSessionCookie(res, sessionId);

			const params = new URLSearchParams({
				client_id: oidcConfig.clientId,
				redirect_uri: `${oidcConfig.baseUrl}/auth/callback`,
				response_type: "code",
				scope: "openid profile email",
				state,
				nonce,
				code_challenge: base64Url(sha256(codeVerifier)),
				code_challenge_method: "S256",
			});

			res.redirect(`${metadata.authorization_endpoint}?${params}`);
		} catch (error) {
			next(error);
		}
	});

	app.get("/auth/callback", async (req, res, next) => {
		try {
			if (!requireOidcEnv(res)) return;
			const session = getSession(req);
			if (!session || !req.query.state || session.state !== req.query.state) {
				res.status(400).send("Invalid login state. Please try again.");
				return;
			}
			if (req.query.error) {
				res.status(401).send(String(req.query.error_description || req.query.error));
				return;
			}

			const metadata = await discoverOidc();
			const body = new URLSearchParams({
				grant_type: "authorization_code",
				code: String(req.query.code || ""),
				redirect_uri: `${oidcConfig.baseUrl}/auth/callback`,
				client_id: oidcConfig.clientId,
				code_verifier: session.codeVerifier,
			});
			const headers = {
				"content-type": "application/x-www-form-urlencoded",
			};

			if (oidcConfig.clientSecret) {
				headers.authorization = `Basic ${Buffer.from(
					`${oidcConfig.clientId}:${oidcConfig.clientSecret}`,
				).toString("base64")}`;
			}

			const tokenResponse = await fetch(metadata.token_endpoint, {
				method: "POST",
				headers,
				body,
			});

			if (!tokenResponse.ok) {
				const errorText = await tokenResponse.text();
				throw new Error(`OIDC token exchange failed: ${errorText}`);
			}

			const tokens = await tokenResponse.json();
			const claims = await verifyIdToken(tokens.id_token, session.nonce, metadata);
			session.user = userFromClaims(claims);
			delete session.state;
			delete session.nonce;
			delete session.codeVerifier;
			res.redirect("/");
		} catch (error) {
			next(error);
		}
	});

	app.post("/auth/logout", (req, res) => {
		const sessionId = getSessionId(req);
		if (sessionId) sessions.delete(sessionId);
		clearSessionCookie(res);
		res.status(204).end();
	});

	app.get("/api/me", (req, res) => {
		const session = getSession(req);
		res.json({ user: session?.user || null });
	});

	app.use(express.static(path.resolve("./public")));

	const server = http.createServer(app);
	const io = new Server();
	const users = new Map();
	const messages = [];
	const maxHistory = 100;

	function getOnlineUsers() {
		return [...users.entries()].map(([id, name]) => ({ id, name }));
	}

	function emitPresence() {
		io.emit("server:presence", {
			count: users.size,
			users: getOnlineUsers(),
		});
	}

	io.attach(server);

	io.use((socket, next) => {
		const fakeReq = {
			headers: {
				cookie: socket.handshake.headers.cookie || "",
			},
		};
		const session = getSession(fakeReq);
		if (!session?.user) {
			next(new Error("Unauthorized"));
			return;
		}
		socket.user = session.user;
		next();
	});

	io.on("connection", (socket) => {
		socket.on("user:join", () => {
			const name = socket.user.name;
			users.set(socket.id, name);
			socket.emit("server:history", {
				messages,
			});
			socket.broadcast.emit("server:system", {
				text: `${name} joined the chat`,
				type: "join",
				at: Date.now(),
			});
			emitPresence();
		});

		socket.on("user:message", (data) => {
			if (!users.has(socket.id)) return;
			const user = users.get(socket.id);
			const message = {
				id: data.id,
				user,
				text: data.text,
				sentAt: data.sentAt || Date.now(),
			};
			messages.push(message);
			if (messages.length > maxHistory) {
				messages.shift();
			}
			socket.broadcast.emit("server:message", message);
		});

		socket.on("user:clear", () => {
			if (!users.has(socket.id)) return;
			const user = users.get(socket.id);
			messages.length = 0;
			io.emit("server:clear", {
				user,
				at: Date.now(),
			});
		});

		socket.on("user:read", (data) => {
			if (!users.has(socket.id)) return;
			socket.broadcast.emit("server:read", {
				messageId: data.messageId,
				reader: users.get(socket.id),
			});
		});

		socket.on("user:typing", (data) => {
			if (!users.has(socket.id)) return;
			const user = users.get(socket.id);
			socket.broadcast.emit("server:typing", {
				user,
			});
		});

		socket.on("disconnect", () => {
			const name = users.get(socket.id);
			users.delete(socket.id);

			if (name) {
				socket.broadcast.emit("server:system", {
					text: `${name} left the chat`,
					type: "leave",
					at: Date.now(),
				});
			}

			emitPresence();
		});
	});

	const port = Number(process.env.PORT || 9000);
	server.listen(port, () => {
		console.log(`Server is listening on port ${port}`);
	});
}

main();
