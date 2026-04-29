import "dotenv/config";
import http from "node:http";
import { Server } from "socket.io";
import path from "node:path";
import express from "express";
import { setupChatSocket } from "./src/app/socket/chat.socket.js";
import authRoutes from "./src/app/auth/auth.routes.js";

async function main() {
	const app = express();
	app.set("trust proxy", 1); // Trust first proxy for correct client IPs if behind a proxy

	app.use(express.json());
	app.use("/auth", authRoutes);

	app.get("/chat", (req, res) => {
		res.sendFile(path.resolve("./public/chat.html"));
	});

	app.use(express.static(path.resolve("./public")));

	const server = http.createServer(app);
	const io = new Server(server, {
		cors: {
			origin: "*",
		},
	});

	// io.use(authMiddleware);

	// Attach Socket.IO to the HTTP server
	io.attach(server);
	setupChatSocket(io);

	const port = Number(process.env.PORT || 9000);
	console.log(process.env);

	server.listen(port, () => {
		console.log(`Server is listening on port ${port}`);
	});
}

main();
