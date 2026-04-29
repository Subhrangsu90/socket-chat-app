import http from "node:http";
import { Server } from "socket.io";
import path from "node:path";
import express from "express";

async function main() {
	const app = express();
	app.set("trust proxy", 1); // Trust first proxy for correct client IPs if behind a proxy

	app.use(express.static(path.resolve("./public")));

	const server = http.createServer(app);
	const io = new Server();
	const users = new Map();
	const messages = [];
	const maxHistory = 100;

	function getOnlineUsers() {
		return [...users.entries()].map(([id, name]) => ({ id, name }));
	}

	// Emit presence update to all clients
	function emitPresence() {
		io.emit("server:presence", {
			count: users.size,
			users: getOnlineUsers(),
		});
	}

	// Attach Socket.IO to the HTTP server
	io.attach(server);

	// Handle Socket.IO connections
	io.on("connect", (socket) => {
		socket.on("user:join", (data) => {
			let name =
				typeof data === "string"
					? data.trim()
					: data?.name?.trim() || "Guest";
			const existingNames = new Set([...users.values()]);
			let baseName = name;
			let suffix = 2;
			while (existingNames.has(name)) {
				name = `${baseName}#${suffix++}`;
			}
			socket.user = { name };
			users.set(socket.id, name);
			// Send user id to client for sidebar highlighting
			socket.emit("server:history", {
				messages,
				userId: socket.id,
				userName: name,
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
				userId: socket.id, // Use socket.id as userId
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

		socket.on("user:delivered", (data) => {
			socket.broadcast.emit("server:delivered", {
				messageId: data.messageId,
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
