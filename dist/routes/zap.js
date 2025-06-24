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
router.post("/Fullscan", zapController_1.startFullScan);
router.get("/getAllScans", zapController_1.getAllScans);
router.delete("/scan/:id", zapController_1.deleteScan);
// router.post('/spider/start', startSpiderScan as any);
// router.get('/spider/status/:scanId', checkSpiderStatus as any);
// router.get('/spider/results/:scanId', getSpiderResults as any);
// router.post('/active/start', startActiveScan as any);
// router.get('/active/status/:scanId', checkActiveScanStatus as any);
// router.get('/scan-sessions', getAllScanSessions);
// router.get('/alerts', getAlerts); // ?baseUrl=https://example.com
exports.default = router;
