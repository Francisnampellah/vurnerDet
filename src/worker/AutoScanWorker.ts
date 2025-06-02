import axios from 'axios';
import { PrismaClient } from '@prisma/client';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const prisma = new PrismaClient();
const ZAP_API_BASE = 'http://zap:8080';
const ZAP_API_KEY = '';
const HUGGINGFACE_API_KEY = process.env.HUGG_FACE_API || "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" ;
const HUGGINGFACE_API_URL = 'https://api-inference.huggingface.co/models/facebook/bart-large-cnn';

const intervalMs = 10000; // 10 seconds
const maxRetries = 5;
const retryDelay = 5000; // 5 seconds

async function waitForDatabase(retries = maxRetries): Promise<void> {
  for (let i = 0; i < retries; i++) {
    try {
      console.log(`Attempting to connect to database (attempt ${i + 1}/${retries})...`);
      await prisma.$connect();
      console.log('Successfully connected to database');
      return;
    } catch (err) {
      console.error(`Database connection attempt ${i + 1} failed:`, err);
      if (i < retries - 1) {
        console.log(`Waiting ${retryDelay}ms before next attempt...`);
        await new Promise(resolve => setTimeout(resolve, retryDelay));
      }
    }
  }
  throw new Error('Failed to connect to database after maximum retries');
}



async function translateAlertToNonTechnical(alert: any): Promise<string> {
  try {
    const response = await axios.post(
      HUGGINGFACE_API_URL,
      {
        inputs: `Translate this security alert into simple, non-technical language: ${alert.description}`,
      },

      {
        headers: {
          'Authorization': `Bearer ${HUGGINGFACE_API_KEY}`,
          'Content-Type': 'application/json',
        },
      }
    );
    return response.data[0].generated_text;
  } catch (error) {
    console.error('Error translating alert:', error);
    return alert.description; // Return original description if translation fails
  }
}



async function updateScans() {
  console.log('Starting scan update cycle...');
  
  try {
    const sessions = await prisma.scanSession.findMany();
    console.log(`Found ${sessions.length} active scan sessions`);

    for (const session of sessions) {
      const { id, spiderId, spiderStatus, activeId, activeStatus, url } = session;
      console.log(`Processing session ${id} for URL: ${url}`);

      try {
        // Update Spider Status
        if (spiderId && spiderStatus < 100) {
          console.log(`Checking spider status for session ${id} (spiderId: ${spiderId})`);
          
          const spiderStatusResp = await axios.get(`${ZAP_API_BASE}/JSON/spider/view/status/`, {
            params: { scanId: spiderId, apikey: ZAP_API_KEY },
          });

          const newStatus = parseInt(spiderStatusResp.data.status);
          console.log(`Spider status for session ${id}: ${newStatus}%`);

          await prisma.scanSession.update({ 
            where: { id }, 
            data: { spiderStatus: newStatus } 
          });

          if (newStatus === 100) {
            console.log(`Spider scan completed for session ${id}, fetching results...`);
            
            const spiderResultsResp = await axios.get(`${ZAP_API_BASE}/JSON/spider/view/results/`, {
              params: { scanId: spiderId, apikey: ZAP_API_KEY },
            });

            await prisma.scanSession.update({
              where: { id },
              data: { 
                spiderResults: spiderResultsResp.data.results as any 
              },
            });
            console.log(`Spider results saved for session ${id}`);

            // Start Active Scan
            console.log(`Starting active scan for session ${id}...`);
            const activeResp = await axios.get(`${ZAP_API_BASE}/JSON/ascan/action/scan/`, {
              params: { url, recurse: true, apikey: ZAP_API_KEY },
            });

            await prisma.scanSession.update({
              where: { id },
              data: { 
                activeId: activeResp.data.scan, 
                activeStatus: 0 
              },
            });
            console.log(`Active scan started for session ${id} with ID: ${activeResp.data.scan}`);
          }
        }

        // Update Active Status
        if (activeId && activeStatus < 100) {
          console.log(`Checking active scan status for session ${id} (activeId: ${activeId})`);
          
          const activeStatusResp = await axios.get(`${ZAP_API_BASE}/JSON/ascan/view/status/`, {
            params: { scanId: activeId, apikey: ZAP_API_KEY },
          });

          const newStatus = parseInt(activeStatusResp.data.status);
          console.log(`Active scan status for session ${id}: ${newStatus}%`);

          await prisma.scanSession.update({ 
            where: { id }, 
            data: { activeStatus: newStatus } 
          });

          if (newStatus === 100) {
            console.log(`Active scan completed for session ${id}, fetching alerts...`);
            
            const alertsResp = await axios.get(`${ZAP_API_BASE}/JSON/core/view/alerts/`, {
              params: { baseurl: url, apikey: ZAP_API_KEY },
            });

            // Translate alerts to non-technical language


            const translatedAlerts = await Promise.all(
              alertsResp.data.alerts.map(async (alert: any) => ({
                nonTechnicalDescription: await translateAlertToNonTechnical(alert)
              }))
            );

            await prisma.scanSession.update({
              where: { id },
              data: { 
                activeResults: alertsResp.data.alerts as any,
                translatedResults: translatedAlerts as any
              },
            });
            console.log(`Active scan results and translations saved for session ${id}`);
          }
        }
      } catch (err: any) {
        console.error(`Error processing session ${id}:`, {
          error: err.message,
          stack: err.stack,
          url,
          spiderId,
          activeId
        });
      }
    }
  } catch (err: any) {
    console.error('Critical error in updateScans:', {
      error: err.message,
      stack: err.stack
    });
  }
  
  console.log('Completed scan update cycle');
}

// Initial run with database connection retry
console.log('Starting AutoScanWorker...');
waitForDatabase()
  .then(() => {
    console.log('Database connection established, starting worker...');
    updateScans().catch(err => {
      console.error('Fatal error in initial run:', err);
    });
  })
  .catch(err => {
    console.error('Failed to connect to database:', err);
    process.exit(1);
  });

// Set up interval
console.log(`Setting up scan interval (${intervalMs}ms)...`);
setInterval(updateScans, intervalMs);
