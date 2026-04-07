const dotenv = require("dotenv");
const app = require("./app");

dotenv.config();

const PORT = Number(process.env.PORT) || 4004;

app.listen(PORT, () => {
	console.log(`API server running on port ${PORT}`);
});
