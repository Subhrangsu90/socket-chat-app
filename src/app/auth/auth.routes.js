import { Router } from "express";
import {
	getCurrentUser,
	handleCallback,
	loginUser,
	logoutUser,
	registerUser,
} from "./auth.controller.js";
import { requireAuth } from "./auth.middleware.js";

const router = Router();

router.get("/login", loginUser);
router.get("/register", registerUser);
router.get("/callback", handleCallback);
router.post("/logout", logoutUser);
router.get("/me", getCurrentUser);

export default router;
