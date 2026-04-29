import * as authService from "./auth.service.js";

const loginUser = async (req, res) => {
	if (!process.env.OIDC_CLIENT_ID || !process.env.OIDC_CLIENT_SECRET) {
		return res.status(500).json({
			message: "OIDC client credentials are not configured.",
		});
	}

	const { loginUrl, state } = authService.createLoginUrl(req);
	authService.setCookie(
		res,
		req,
		authService.STATE_COOKIE_NAME,
		state,
		10 * 60,
	);

	return res.redirect(loginUrl.toString());
};

const registerUser = async (req, res) => {
	if (!process.env.OIDC_CLIENT_ID || !process.env.OIDC_CLIENT_SECRET) {
		return res.status(500).json({
			message: "OIDC client credentials are not configured.",
		});
	}

	const { registerUrl, state } = authService.createRegisterUrl(req);
	authService.setCookie(
		res,
		req,
		authService.STATE_COOKIE_NAME,
		state,
		10 * 60,
	);

	return res.redirect(registerUrl.toString());
};

const handleCallback = async (req, res) => {
	try {
		const { code, state } = req.query;
		const cookies = authService.parseCookies(req);

		if (!code || typeof code !== "string") {
			return res.status(400).send("Missing authorization code.");
		}

		if (
			!state ||
			typeof state !== "string" ||
			state !== cookies[authService.STATE_COOKIE_NAME]
		) {
			return res.status(400).send("Invalid login state.");
		}

		const tokenResponse = await authService.exchangeCodeForToken(req, code);

		authService.setCookie(
			res,
			req,
			authService.AUTH_COOKIE_NAME,
			tokenResponse.access_token,
			tokenResponse.expires_in,
		);

		authService.clearCookie(res, req, authService.STATE_COOKIE_NAME);

		return res.redirect("/chat");
	} catch (error) {
		console.error("OIDC callback failed", error);
		return res.status(500).send("Unable to complete login.");
	}
};

const logoutUser = async (req, res) => {
	await authService.revokeToken(req);
	authService.clearCookie(res, req, authService.AUTH_COOKIE_NAME);
	authService.clearCookie(res, req, authService.STATE_COOKIE_NAME);

	return res.status(200).json({ ok: true });
};

const getCurrentUser = async (req, res) => {
	try {
		const user = await authService.fetchCurrentUser(req);

		if (!user) {
			return res.status(401).json({ authenticated: false });
		}

		return res.json({
			authenticated: true,
			user,
		});
	} catch (error) {
		console.error("Unable to load current user", error);
		return res.status(500).json({
			message: "Unable to load current user.",
		});
	}
};

export { getCurrentUser, handleCallback, loginUser, logoutUser, registerUser };
