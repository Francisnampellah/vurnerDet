"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.deleteScan = exports.getScanById = exports.getAllScans = exports.startFullScan = void 0;
const axios_1 = __importDefault(require("axios"));
const client_1 = require("@prisma/client");
const dns_1 = __importDefault(require("dns"));
const util_1 = require("util");
const prisma = new client_1.PrismaClient();
const ZAP_API_BASE = 'http://zap:8080';
const ZAP_API_KEY = '';
const resolveDNS = (0, util_1.promisify)(dns_1.default.lookup);
async function getTargetMetadata(url) {
    try {
        // Extract hostname from URL
        const hostname = new URL(url).hostname;
        // Resolve IP address
        const { address: ipAddress } = await resolveDNS(hostname);
        // Get initial response to extract headers
        const response = await axios_1.default.get(url, {
            maxRedirects: 5,
            validateStatus: () => true // Accept any status code
        });
        // Extract web server info
        const webServer = response.headers['server'] || response.headers['x-powered-by'] || 'Unknown';
        // Extract authentication method
        const authHeader = response.headers['www-authenticate'] || response.headers['authorization'];
        const authenticationMethod = authHeader ? authHeader.split(' ')[0] : null;
        return {
            ipAddress,
            webServer,
            authenticationMethod
        };
    }
    catch (error) {
        console.error('Error getting target metadata:', error);
        return {
            ipAddress: null,
            webServer: null,
            authenticationMethod: null
        };
    }
}
async function getDetectedTechnologies(url) {
    try {
        // Enable passive scanning for the target
        await axios_1.default.get(`${ZAP_API_BASE}/JSON/pscan/action/enableAllScanners/`, {
            params: { apikey: ZAP_API_KEY }
        });
        // Add the URL to the sites tree
        await axios_1.default.get(`${ZAP_API_BASE}/JSON/core/action/accessUrl/`, {
            params: { url, apikey: ZAP_API_KEY }
        });
        // Wait a bit for passive scanning to detect technologies
        await new Promise(resolve => setTimeout(resolve, 5000));
        // Get the detected technologies
        const response = await axios_1.default.get(`${ZAP_API_BASE}/JSON/pscan/view/technologies/`, {
            params: { apikey: ZAP_API_KEY }
        });
        return response.data.technologies || [];
    }
    catch (error) {
        console.error('Error getting detected technologies:', error);
        return [];
    }
}
const startFullScan = async (req, res) => {
    const { url } = req.body;
    const userId = req.user?.id;
    try {
        if (!url)
            return res.status(400).json({ error: 'URL is required' });
        if (!userId)
            return res.status(401).json({ error: 'User not authenticated' });
        // Get metadata first to check if site is accessible
        const metadata = await getTargetMetadata(url);
        // Check if IP address is null, indicating site is not accessible
        if (!metadata.ipAddress) {
            return res.status(400).json({
                success: false,
                error: 'Failed to initiate scan: Target site is not accessible or cannot be resolved'
            });
        }
        // Check if there's an existing scan for this URL by any user
        const existingScan = await prisma.scanSession.findFirst({
            where: { url }
        });
        if (existingScan) {
            // Check if this user already has a copy of this scan
            const userScan = await prisma.scanSession.findFirst({
                where: {
                    url,
                    userId
                }
            });
            if (userScan) {
                return res.status(400).json({ error: 'You already have a scan for this URL' });
            }
            // Create a new scan session for this user by copying the existing scan data
            const scanData = {
                url,
                ipAddress: existingScan.ipAddress,
                webServer: existingScan.webServer,
                authenticationMethod: existingScan.authenticationMethod,
                technologies: existingScan.technologies,
                spiderId: existingScan.spiderId,
                activeId: existingScan.activeId,
                spiderStatus: existingScan.spiderStatus,
                activeStatus: existingScan.activeStatus,
                spiderResults: existingScan.spiderResults,
                activeResults: existingScan.activeResults,
                translatedResults: existingScan.translatedResults
            };
            const newSession = await prisma.scanSession.create({
                data: {
                    ...scanData,
                    userId,
                },
            });
            return res.status(201).json({
                success: true,
                message: 'Scan data copied successfully',
                data: newSession
            });
        }
        // If no existing scan, proceed with new scan
        // const technologies = await getDetectedTechnologies(url);
        const spiderResp = await axios_1.default.get(`${ZAP_API_BASE}/JSON/spider/action/scan/`, {
            params: { url, apikey: ZAP_API_KEY },
        });
        const spiderId = spiderResp.data.scan;
        const session = await prisma.scanSession.create({
            data: {
                url,
                ipAddress: metadata.ipAddress,
                webServer: metadata.webServer,
                authenticationMethod: metadata.authenticationMethod,
                technologies: [],
                spiderId,
                spiderStatus: 0,
                userId,
            },
        });
        return res.status(201).json({
            success: true,
            message: 'New scan started successfully',
            data: session
        });
    }
    catch (err) {
        console.error('Start scan error:', err.message);
        return res.status(500).json({
            success: false,
            error: 'Failed to start scan',
            details: err.message
        });
    }
};
exports.startFullScan = startFullScan;
const getAllScans = async (req, res) => {
    const userId = req.user?.id; // Get user ID from auth middleware
    const userRole = req.user?.role; // Get user role from auth middleware
    try {
        if (!userId)
            return res.status(401).json({ error: 'User not authenticated' });
        let scans;
        if (userRole === 'ADMIN') {
            // Admin: get all scans
            scans = await prisma.scanSession.findMany({
                orderBy: { createdAt: 'desc' }
            });
        }
        else {
            // Regular user: only get their scans
            scans = await prisma.scanSession.findMany({
                where: { userId },
                orderBy: { createdAt: 'desc' }
            });
        }
        return res.status(200).json({
            success: true,
            data: scans
        });
    }
    catch (err) {
        console.error('Get all scans error:', err.message);
        return res.status(500).json({
            success: false,
            error: 'Failed to fetch scans'
        });
    }
};
exports.getAllScans = getAllScans;
// Add a new endpoint to get a specific scan
const getScanById = async (req, res) => {
    const { id } = req.params;
    const userId = req.user?.id;
    try {
        if (!userId)
            return res.status(401).json({ error: 'User not authenticated' });
        const scan = await prisma.scanSession.findFirst({
            where: {
                id: parseInt(id),
                userId // Ensure the scan belongs to the user
            }
        });
        if (!scan) {
            return res.status(404).json({
                success: false,
                error: 'Scan not found or access denied'
            });
        }
        return res.status(200).json({
            success: true,
            data: scan
        });
    }
    catch (err) {
        console.error('Get scan error:', err.message);
        return res.status(500).json({
            success: false,
            error: 'Failed to fetch scan'
        });
    }
};
exports.getScanById = getScanById;
const deleteScan = async (req, res) => {
    const { id } = req.params;
    const userId = req.user?.id;
    try {
        if (!userId)
            return res.status(401).json({ error: 'User not authenticated' });
        // Find the scan and verify ownership
        const scan = await prisma.scanSession.findFirst({
            where: {
                id: parseInt(id),
                userId // Ensure the scan belongs to the user
            }
        });
        if (!scan) {
            return res.status(404).json({
                success: false,
                error: 'Scan not found or access denied'
            });
        }
        // Delete the scan
        await prisma.scanSession.delete({
            where: {
                id: parseInt(id)
            }
        });
        return res.status(200).json({
            success: true,
            message: 'Scan deleted successfully'
        });
    }
    catch (err) {
        console.error('Delete scan error:', err.message);
        return res.status(500).json({
            success: false,
            error: 'Failed to delete scan'
        });
    }
};
exports.deleteScan = deleteScan;
// import axios from 'axios';
// import { Request, Response } from 'express';
// import { PrismaClient } from '@prisma/client';
// const prisma = new PrismaClient();
// // ZAP API base URL - using Docker service name
// const ZAP_API_BASE = 'http://zap:8080';
// // Optional: Replace with your API key if enabled
// const ZAP_API_KEY = ''; // e.g., '1234567890abcdef'
// export const startSpiderScan = async (req: Request, res: Response) => {
//   const { url } = req.body;
//   try {
//     // Check if there's already a scan session for this URL
//     const existingSession = await prisma.scanSession.findFirst({
//       where: { url }
//     });
//     if (existingSession) {
//       return res.status(400).json({ error: 'A scan session already exists for this URL' });
//     }
//     const response = await axios.get(`${ZAP_API_BASE}/JSON/spider/action/scan/`, {
//       params: {
//         url,
//         apikey: ZAP_API_KEY,
//       },
//     });
//     // Create a new scan session
//     const scanSession = await prisma.scanSession.create({
//       data: {
//         url,
//         spiderId: response.data.scan,
//         spiderStatus: 0,
//       },
//     });
//     res.json({ scanId: response.data.scan, sessionId: scanSession.id });
//   } catch (err: any) {
//     console.error('Spider scan error:', err.message);
//     res.status(500).json({ error: 'Failed to start spider scan' });
//   }
// };
// export const checkSpiderStatus = async (req: Request, res: Response) => {
//   const { scanId } = req.params;
//   try {
//     const response = await axios.get(`${ZAP_API_BASE}/JSON/spider/view/status/`, {
//       params: {
//         scanId,
//         apikey: ZAP_API_KEY,
//       },
//     });
//     // Update the scan session with the new spider status
//     await prisma.scanSession.updateMany({
//       where: { spiderId: scanId },
//       data: { spiderStatus: parseInt(response.data.status) },
//     });
//     res.json({ status: response.data.status });
//   } catch (err: any) {
//     console.error('Spider status error:', err.message);
//     res.status(500).json({ error: 'Failed to get spider status' });
//   }
// };
// export const startActiveScan = async (req: Request, res: Response) => {
//   const { url } = req.body;
//   try {
//     // Check if there's an active scan in progress for this URL
//     const existingSession = await prisma.scanSession.findFirst({
//       where: { 
//         url,
//         activeStatus: {
//           gt: 0
//         }
//       }
//     });
//     if (existingSession) {
//       return res.status(400).json({ error: 'An active scan is already in progress for this URL' });
//     }
//     const response = await axios.get(`${ZAP_API_BASE}/JSON/ascan/action/scan/`, {
//       params: {
//         url,
//         recurse: true,
//         apikey: ZAP_API_KEY,
//       },
//     });
//     // Find existing scan session or create new one
//     let scanSession = await prisma.scanSession.findFirst({
//       where: { url }
//     });
//     if (scanSession) {
//       // Update existing session
//       scanSession = await prisma.scanSession.update({
//         where: { id: scanSession.id },
//         data: {
//           activeId: response.data.scan,
//           activeStatus: 0,
//         },
//       });
//     } else {
//       // Create new session
//       scanSession = await prisma.scanSession.create({
//         data: {
//           url,
//           activeId: response.data.scan,
//           activeStatus: 0,
//         },
//       });
//     }
//     res.json({ scanId: response.data.scan, sessionId: scanSession.id });
//   } catch (err: any) {
//     console.error('Active scan error:', err.message);
//     res.status(500).json({ error: 'Failed to start active scan' });
//   }
// };
// export const checkActiveScanStatus = async (req: Request, res: Response) => {
//   const { scanId } = req.params;
//   try {
//     const response = await axios.get(`${ZAP_API_BASE}/JSON/ascan/view/status/`, {
//       params: {
//         scanId,
//         apikey: ZAP_API_KEY,
//       },
//     });
//     // Update the scan session with the new active scan status
//     await prisma.scanSession.updateMany({
//       where: { activeId: scanId },
//       data: { activeStatus: parseInt(response.data.status) },
//     });
//     res.json({ status: response.data.status });
//   } catch (err: any) {
//     console.error('Active scan status error:', err.message);
//     res.status(500).json({ error: 'Failed to get active scan status' });
//   }
// };
// export const getAlerts = async (req: Request, res: Response) => {
//   const { baseUrl } = req.query;
//   try {
//     const response = await axios.get(`${ZAP_API_BASE}/JSON/core/view/alerts/`, {
//       params: {
//         baseurl: baseUrl,
//         apikey: ZAP_API_KEY,
//       },
//     });
//     // Find the scan session for this URL and update active results
//     await prisma.scanSession.updateMany({
//       where: { url: baseUrl as string },
//       data: { activeResults: response.data.alerts },
//     });
//     res.json({ alerts: response.data.alerts });
//   } catch (err: any) {
//     console.error('Get alerts error:', err.message);
//     res.status(500).json({ error: 'Failed to get alerts' });
//   }
// };
// export const getAllScanSessions = async (req: Request, res: Response) => {
//   try {
//     const scanSessions = await prisma.scanSession.findMany({
//       orderBy: {
//         createdAt: 'desc'
//       }
//     });
//     res.json({ scanSessions });
//   } catch (err: any) {
//     console.error('Get scan sessions error:', err.message);
//     res.status(500).json({ error: 'Failed to get scan sessions' });
//   }
// };
// export const getSpiderResults = async (req: Request, res: Response) => {
//   const { scanId } = req.params;
//   try {
//     // Get the spider results
//     const response = await axios.get(`${ZAP_API_BASE}/JSON/spider/view/results/`, {
//       params: {
//         scanId,
//         apikey: ZAP_API_KEY,
//       },
//     });
//     // Get the spider status
//     const statusResponse = await axios.get(`${ZAP_API_BASE}/JSON/spider/view/status/`, {
//       params: {
//         scanId,
//         apikey: ZAP_API_KEY,
//       },
//     });
//     // Update the scan session with spider results
//     await prisma.scanSession.updateMany({
//       where: { spiderId: scanId },
//       data: { 
//         spiderResults: response.data.results,
//         spiderStatus: parseInt(statusResponse.data.status)
//       },
//     });
//     res.json({
//       urls: response.data.results,
//       status: statusResponse.data.status
//     });
//   } catch (err: any) {
//     console.error('Get spider results error:', err.message);
//     res.status(500).json({ error: 'Failed to get spider results' });
//   }
// };
