"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const auth_1 = require("../middleware/auth");
const zapController_1 = require("../controllers/zapController");
const router = express_1.default.Router();
// Apply auth middleware to all routes 
router.use(auth_1.auth);
router.post('/spider/start', zapController_1.startSpiderScan);
router.get('/spider/status/:scanId', zapController_1.checkSpiderStatus);
router.get('/spider/results/:scanId', zapController_1.getSpiderResults);
router.post('/active/start', zapController_1.startActiveScan);
router.get('/active/status/:scanId', zapController_1.checkActiveScanStatus);
router.get('/scan-sessions', zapController_1.getAllScanSessions);
router.get('/alerts', zapController_1.getAlerts); // ?baseUrl=https://example.com
exports.default = router;
