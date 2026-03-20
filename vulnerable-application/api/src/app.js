const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

app.get("/health", (_req, res) => {
	res.status(200).json({ status: "ok" });
});

app.use((req, res) => {
	res.status(404).json({
		message: `Route not found: ${req.method} ${req.originalUrl}`,
	});
});

app.use((err, _req, res, _next) => {
	const statusCode = err.status || 500;
	const message = err.message || "Internal Server Error";

	res.status(statusCode).json({ message });
});

module.exports = app;
