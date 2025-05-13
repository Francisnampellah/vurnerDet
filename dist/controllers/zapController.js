"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getSpiderResults = exports.getAllScanSessions = exports.getAlerts = exports.checkActiveScanStatus = exports.startActiveScan = exports.checkSpiderStatus = exports.startSpiderScan = void 0;
const axios_1 = __importDefault(require("axios"));
const client_1 = require("@prisma/client");
const prisma = new client_1.PrismaClient();
// ZAP API base URL - using Docker service name
const ZAP_API_BASE = 'http://zap:8080';
// Optional: Replace with your API key if enabled
const ZAP_API_KEY = ''; // e.g., '1234567890abcdef'
const startSpiderScan = async (req, res) => {
    const { url } = req.body;
    try {
        // Check if there's already a scan session for this URL
        const existingSession = await prisma.scanSession.findFirst({
            where: { url }
        });
        if (existingSession) {
            return res.status(400).json({ error: 'A scan session already exists for this URL' });
        }
        const response = await axios_1.default.get(`${ZAP_API_BASE}/JSON/spider/action/scan/`, {
            params: {
                url,
                apikey: ZAP_API_KEY,
            },
        });
        // Create a new scan session
        const scanSession = await prisma.scanSession.create({
            data: {
                url,
                spiderId: response.data.scan,
                spiderStatus: 0,
            },
        });
        res.json({ scanId: response.data.scan, sessionId: scanSession.id });
    }
    catch (err) {
        console.error('Spider scan error:', err.message);
        res.status(500).json({ error: 'Failed to start spider scan' });
    }
};
exports.startSpiderScan = startSpiderScan;
const checkSpiderStatus = async (req, res) => {
    const { scanId } = req.params;
    try {
        const response = await axios_1.default.get(`${ZAP_API_BASE}/JSON/spider/view/status/`, {
            params: {
                scanId,
                apikey: ZAP_API_KEY,
            },
        });
        // Update the scan session with the new spider status
        await prisma.scanSession.updateMany({
            where: { spiderId: scanId },
            data: { spiderStatus: parseInt(response.data.status) },
        });
        res.json({ status: response.data.status });
    }
    catch (err) {
        console.error('Spider status error:', err.message);
        res.status(500).json({ error: 'Failed to get spider status' });
    }
};
exports.checkSpiderStatus = checkSpiderStatus;
const startActiveScan = async (req, res) => {
    const { url } = req.body;
    try {
        // Check if there's an active scan in progress for this URL
        const existingSession = await prisma.scanSession.findFirst({
            where: {
                url,
                activeStatus: {
                    gt: 0
                }
            }
        });
        if (existingSession) {
            return res.status(400).json({ error: 'An active scan is already in progress for this URL' });
        }
        const response = await axios_1.default.get(`${ZAP_API_BASE}/JSON/ascan/action/scan/`, {
            params: {
                url,
                recurse: true,
                apikey: ZAP_API_KEY,
            },
        });
        // Find existing scan session or create new one
        let scanSession = await prisma.scanSession.findFirst({
            where: { url }
        });
        if (scanSession) {
            // Update existing session
            scanSession = await prisma.scanSession.update({
                where: { id: scanSession.id },
                data: {
                    activeId: response.data.scan,
                    activeStatus: 0,
                },
            });
        }
        else {
            // Create new session
            scanSession = await prisma.scanSession.create({
                data: {
                    url,
                    activeId: response.data.scan,
                    activeStatus: 0,
                },
            });
        }
        res.json({ scanId: response.data.scan, sessionId: scanSession.id });
    }
    catch (err) {
        console.error('Active scan error:', err.message);
        res.status(500).json({ error: 'Failed to start active scan' });
    }
};
exports.startActiveScan = startActiveScan;
const checkActiveScanStatus = async (req, res) => {
    const { scanId } = req.params;
    try {
        const response = await axios_1.default.get(`${ZAP_API_BASE}/JSON/ascan/view/status/`, {
            params: {
                scanId,
                apikey: ZAP_API_KEY,
            },
        });
        // Update the scan session with the new active scan status
        await prisma.scanSession.updateMany({
            where: { activeId: scanId },
            data: { activeStatus: parseInt(response.data.status) },
        });
        res.json({ status: response.data.status });
    }
    catch (err) {
        console.error('Active scan status error:', err.message);
        res.status(500).json({ error: 'Failed to get active scan status' });
    }
};
exports.checkActiveScanStatus = checkActiveScanStatus;
const getAlerts = async (req, res) => {
    const { baseUrl } = req.query;
    try {
        const response = await axios_1.default.get(`${ZAP_API_BASE}/JSON/core/view/alerts/`, {
            params: {
                baseurl: baseUrl,
                apikey: ZAP_API_KEY,
            },
        });
        res.json({ alerts: response.data.alerts });
    }
    catch (err) {
        console.error('Get alerts error:', err.message);
        res.status(500).json({ error: 'Failed to get alerts' });
    }
};
exports.getAlerts = getAlerts;
const getAllScanSessions = async (req, res) => {
    try {
        const scanSessions = await prisma.scanSession.findMany({
            orderBy: {
                createdAt: 'desc'
            }
        });
        res.json({ scanSessions });
    }
    catch (err) {
        console.error('Get scan sessions error:', err.message);
        res.status(500).json({ error: 'Failed to get scan sessions' });
    }
};
exports.getAllScanSessions = getAllScanSessions;
const getSpiderResults = async (req, res) => {
    const { scanId } = req.params;
    try {
        // Get the spider results
        const response = await axios_1.default.get(`${ZAP_API_BASE}/JSON/spider/view/results/`, {
            params: {
                scanId,
                apikey: ZAP_API_KEY,
            },
        });
        // Get the spider status
        const statusResponse = await axios_1.default.get(`${ZAP_API_BASE}/JSON/spider/view/status/`, {
            params: {
                scanId,
                apikey: ZAP_API_KEY,
            },
        });
        res.json({
            urls: response.data.results,
            status: statusResponse.data.status
        });
    }
    catch (err) {
        console.error('Get spider results error:', err.message);
        res.status(500).json({ error: 'Failed to get spider results' });
    }
};
exports.getSpiderResults = getSpiderResults;
