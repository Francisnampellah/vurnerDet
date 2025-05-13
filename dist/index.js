"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const dotenv_1 = __importDefault(require("dotenv"));
const cors_1 = __importDefault(require("cors"));
const auth_1 = __importDefault(require("./routes/auth"));
const auth_2 = require("./middleware/auth");
const zap_1 = __importDefault(require("./routes/zap"));
// Load environment variables
dotenv_1.default.config();
const app = (0, express_1.default)();
const PORT = process.env.PORT || 3000;
// Middleware
app.use((0, cors_1.default)()); // Enable CORS for all routes
app.use(express_1.default.json());
// Routes
app.use('/api/auth', auth_1.default);
app.use('/api/scan', zap_1.default);
// Protected route example
app.get('/api/protected', auth_2.auth, (_req, res) => {
    res.json({ message: 'This is a protected route' });
});
app.get('/', (_req, res) => {
    res.send('Hello, TypeScript!');
});
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
