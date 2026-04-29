import { fetchCurrentUser } from "./auth.service.js";

export async function requireAuth(req, res, next) {
	try {
		const user = await fetchCurrentUser(req);

		if (!user) {
			return res.status(401).json({ message: "Authentication required." });
		}

		req.user = user;
		return next();
	} catch (error) {
		return res.status(401).json({ message: "Authentication required." });
	}
}
