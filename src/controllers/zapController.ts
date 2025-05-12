import axios from 'axios';
import { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

// ZAP API base URL - using Docker service name
const ZAP_API_BASE = 'http://zap:8080';

// Optional: Replace with your API key if enabled
const ZAP_API_KEY = ''; // e.g., '1234567890abcdef'

export const startSpiderScan = async (req: Request, res: Response) => {
  const { url } = req.body;

  try {
    const response = await axios.get(`${ZAP_API_BASE}/JSON/spider/action/scan/`, {
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
  } catch (err: any) {
    console.error('Spider scan error:', err.message);
    res.status(500).json({ error: 'Failed to start spider scan' });
  }
};

export const checkSpiderStatus = async (req: Request, res: Response) => {
  const { scanId } = req.params;

  try {
    const response = await axios.get(`${ZAP_API_BASE}/JSON/spider/view/status/`, {
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
  } catch (err: any) {
    console.error('Spider status error:', err.message);
    res.status(500).json({ error: 'Failed to get spider status' });
  }
};

export const startActiveScan = async (req: Request, res: Response) => {
  const { url } = req.body;

  try {
    const response = await axios.get(`${ZAP_API_BASE}/JSON/ascan/action/scan/`, {
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
    } else {
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
  } catch (err: any) {
    console.error('Active scan error:', err.message);
    res.status(500).json({ error: 'Failed to start active scan' });
  }
};

export const checkActiveScanStatus = async (req: Request, res: Response) => {
  const { scanId } = req.params;

  try {
    const response = await axios.get(`${ZAP_API_BASE}/JSON/ascan/view/status/`, {
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
  } catch (err: any) {
    console.error('Active scan status error:', err.message);
    res.status(500).json({ error: 'Failed to get active scan status' });
  }
};

export const getAlerts = async (req: Request, res: Response) => {
  const { baseUrl } = req.query;

  try {
    const response = await axios.get(`${ZAP_API_BASE}/JSON/core/view/alerts/`, {
      params: {
        baseurl: baseUrl,
        apikey: ZAP_API_KEY,
      },
    });

    res.json({ alerts: response.data.alerts });
  } catch (err: any) {
    console.error('Get alerts error:', err.message);
    res.status(500).json({ error: 'Failed to get alerts' });
  }
};

export const getAllScanSessions = async (req: Request, res: Response) => {
  try {
    const scanSessions = await prisma.scanSession.findMany({
      orderBy: {
        createdAt: 'desc'
      }
    });

    res.json({ scanSessions });
  } catch (err: any) {
    console.error('Get scan sessions error:', err.message);
    res.status(500).json({ error: 'Failed to get scan sessions' });
  }
};

export const getSpiderResults = async (req: Request, res: Response) => {
  const { scanId } = req.params;

  try {
    // Get the spider results
    const response = await axios.get(`${ZAP_API_BASE}/JSON/spider/view/results/`, {
      params: {
        scanId,
        apikey: ZAP_API_KEY,
      },
    });

    // Get the spider status
    const statusResponse = await axios.get(`${ZAP_API_BASE}/JSON/spider/view/status/`, {
      params: {
        scanId,
        apikey: ZAP_API_KEY,
      },
    });

    res.json({
      urls: response.data.results,
      status: statusResponse.data.status
    });
  } catch (err: any) {
    console.error('Get spider results error:', err.message);
    res.status(500).json({ error: 'Failed to get spider results' });
  }
};
