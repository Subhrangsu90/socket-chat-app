export function setupChatSocket(io) {
	const users = new Map();
	const messages = [];
	const maxHistory = 100;

	function getOnlineUsers() {
		return [...users.values()].map((user) => ({
			id: user.userId,
			name: user.name,
			socketId: user.socketId,
		}));
	}

	function getSocketUser(socket) {
		return users.get(socket.id);
	}

	function emitPresence() {
		io.emit("server:presence", {
			count: users.size,
			users: getOnlineUsers(),
		});
	}

	io.on("connect", (socket) => {
		socket.on("user:join", (data) => {
			let name =
				typeof data === "string"
					? data.trim()
					: data?.name?.trim() || "Guest";
			const userId =
				typeof data?.id === "string" && data.id.trim()
					? data.id.trim()
					: socket.id;
			const existingNames = new Set(
				[...users.values()]
					.filter((user) => user.userId !== userId)
					.map((user) => user.name)
			);
			const baseName = name;
			let suffix = 2;

			while (existingNames.has(name)) {
				name = `${baseName}#${suffix++}`;
			}

			const user = {
				userId,
				socketId: socket.id,
				name,
				email: typeof data?.email === "string" ? data.email : undefined,
				picture: typeof data?.picture === "string" ? data.picture : undefined,
			};

			socket.user = user;
			users.set(socket.id, user);

			socket.emit("server:history", {
				messages,
				userId: user.userId,
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

			const user = getSocketUser(socket);
			const message = {
				id: data.id,
				user: user.name,
				userId: user.userId,
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

			const user = getSocketUser(socket);
			messages.length = 0;
			io.emit("server:clear", {
				user: user.name,
				at: Date.now(),
			});
		});

		socket.on("user:read", (data) => {
			if (!users.has(socket.id)) return;

			socket.broadcast.emit("server:read", {
				messageId: data.messageId,
				reader: getSocketUser(socket).name,
			});
		});

		socket.on("user:delivered", (data) => {
			socket.broadcast.emit("server:delivered", {
				messageId: data.messageId,
			});
		});

		socket.on("user:typing", () => {
			if (!users.has(socket.id)) return;

			const user = getSocketUser(socket);
			socket.broadcast.emit("server:typing", {
				user: user.name,
			});
		});

		socket.on("disconnect", () => {
			const user = getSocketUser(socket);
			users.delete(socket.id);

			if (user) {
				socket.broadcast.emit("server:system", {
					text: `${user.name} left the chat`,
					type: "leave",
					at: Date.now(),
				});
			}

			emitPresence();
		});
	});
}
