import express from 'express';
import { auth } from '../middleware/auth';
import {
  // startSpiderScan,
  // checkSpiderStatus,
  // startActiveScan,
  // checkActiveScanStatus,
  // getAlerts,
  // getAllScanSessions,
  // getSpiderResults,
  startFullScan,
  getAllScans,
} from '../controllers/zapController';

const router = express.Router();

// Apply auth middleware to all routes 
router.use(auth);


router.post("/Fullscan",startFullScan as any)
router.get("/getAllScans",getAllScans as any)

// router.post('/spider/start', startSpiderScan as any);
// router.get('/spider/status/:scanId', checkSpiderStatus as any);
// router.get('/spider/results/:scanId', getSpiderResults as any);
// router.post('/active/start', startActiveScan as any);
// router.get('/active/status/:scanId', checkActiveScanStatus as any);

// router.get('/scan-sessions', getAllScanSessions);

// router.get('/alerts', getAlerts); // ?baseUrl=https://example.com

export default router;
