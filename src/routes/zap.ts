import express from 'express';
import { auth } from '../middleware/auth';
import {
  startSpiderScan,
  checkSpiderStatus,
  startActiveScan,
  checkActiveScanStatus,
  getAlerts,
  getAllScanSessions,
  getSpiderResults,
} from '../controllers/zapController';

const router = express.Router();

// Apply auth middleware to all routes
router.use(auth);

router.post('/spider/start', startSpiderScan);
router.get('/spider/status/:scanId', checkSpiderStatus);
router.get('/spider/results/:scanId', getSpiderResults);
router.post('/active/start', startActiveScan);
router.get('/active/status/:scanId', checkActiveScanStatus);

router.get('/scan-sessions', getAllScanSessions);

router.get('/alerts', getAlerts); // ?baseUrl=https://example.com

export default router;
