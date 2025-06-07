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

// Define interfaces for ZAP API responses
interface ZapSpiderStatusResponse {
  status: string;
}

interface ZapSpiderResultsResponse {
  results: any[];
}

interface ZapActiveScanResponse {
  scan: string;
}

interface ZapAlertsResponse {
  alerts: any[];
}

// Enhanced configuration for API calls
const API_CONFIG = {
  timeout: 30000, // 30 seconds timeout
  headers: {
    'Content-Type': 'application/json',
  },
  maxRedirects: 5,
  validateStatus: (status: number) => status >= 200 && status < 500 // Accept all responses except 5xx errors
};

// Rate limiting and retry configuration
const RATE_LIMIT_DELAY = 2000; // 2 seconds delay between API calls
const MAX_RETRIES = 3;
const INITIAL_RETRY_DELAY = 1000; // 1 second

// Helper function for exponential backoff
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

// Helper function to check if target is reachable
async function isTargetReachable(url: string): Promise<boolean> {
  try {
    const response = await axios.get(url, {
      timeout: 10000,
      validateStatus: (status) => status < 500 // Accept any response that's not a server error
    });
    return true;
  } catch (error: any) {
    console.error(`Target ${url} is not reachable:`, error.message);
    return false;
  }
}

// Helper function for making API calls with retry logic
async function makeZapApiCall<T>(
  endpoint: string,
  params: any,
  retryCount = 0
): Promise<T> {
  try {
    await delay(RATE_LIMIT_DELAY);
    const response = await axios.get(`${ZAP_API_BASE}${endpoint}`, {
      params: { ...params, apikey: ZAP_API_KEY },
      ...API_CONFIG
    });
    return response.data as T;
  } catch (error: any) {
    if (retryCount < MAX_RETRIES) {
      const backoffDelay = INITIAL_RETRY_DELAY * Math.pow(2, retryCount);
      console.log(`API call failed, retrying in ${backoffDelay}ms (attempt ${retryCount + 1}/${MAX_RETRIES})`);
      await delay(backoffDelay);
      return makeZapApiCall<T>(endpoint, params, retryCount + 1);
    }
    throw new Error(`ZAP API call failed after ${MAX_RETRIES} retries: ${error.message}`);
  }
}

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
    console.log(`Making translation request for alert: ${alert.name}`);
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

    if (!response.data || !response.data[0]) {
      console.error('Invalid response format from Hugging Face API:', JSON.stringify(response.data));
      return alert.description;
    }

    // Handle both possible response formats
    const translatedText = response.data[0].summary_text || response.data[0].generated_text;
    
    if (!translatedText) {
      console.error('No translation text found in response:', JSON.stringify(response.data));
      return alert.description;
    }

    console.log(`Successfully translated alert. Original: "${alert.description.substring(0, 100)}..." -> Translated: "${translatedText.substring(0, 100)}..."`);
    return translatedText;
  } catch (error: any) {
    console.error('Error translating alert:', {
      error: error.message,
      response: error.response?.data,
      alertName: alert.name
    });
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
        // Check if target is reachable before proceeding
        const isReachable = await isTargetReachable(url);
        if (!isReachable) {
          console.error(`Target ${url} is not reachable, skipping scan session ${id}`);
          continue;
        }

        // Update Spider Status
        if (spiderId && spiderStatus < 100) {
          console.log(`Checking spider status for session ${id} (spiderId: ${spiderId})`);
          
          const spiderStatusResp = await makeZapApiCall<ZapSpiderStatusResponse>('/JSON/spider/view/status/', { scanId: spiderId });
          const newStatus = parseInt(spiderStatusResp.status);
          console.log(`Spider status for session ${id}: ${newStatus}%`);

          await prisma.scanSession.update({ 
            where: { id }, 
            data: { spiderStatus: newStatus } 
          });

          if (newStatus === 100) {
            console.log(`Spider scan completed for session ${id}, fetching results...`);
            
            const spiderResultsResp = await makeZapApiCall<ZapSpiderResultsResponse>('/JSON/spider/view/results/', { scanId: spiderId });

            await prisma.scanSession.update({
              where: { id },
              data: { 
                spiderResults: spiderResultsResp.results as any 
              },
            });
            console.log(`Spider results saved for session ${id}`);

            // Start Active Scan
            console.log(`Starting active scan for session ${id}...`);
            const activeResp = await makeZapApiCall<ZapActiveScanResponse>('/JSON/ascan/action/scan/', { url, recurse: true });

            await prisma.scanSession.update({
              where: { id },
              data: { 
                activeId: activeResp.scan, 
                activeStatus: 0 
              },
            });
            console.log(`Active scan started for session ${id} with ID: ${activeResp.scan}`);
          }
        }

        // Update Active Status
        if (activeId && activeStatus < 100) {
          console.log(`Checking active scan status for session ${id} (activeId: ${activeId})`);
          
          const activeStatusResp = await makeZapApiCall<ZapSpiderStatusResponse>('/JSON/ascan/view/status/', { scanId: activeId });
          const newStatus = parseInt(activeStatusResp.status);
          console.log(`Active scan status for session ${id}: ${newStatus}%`);

          await prisma.scanSession.update({ 
            where: { id }, 
            data: { activeStatus: newStatus } 
          });

          if (newStatus === 100) {
            console.log(`Active scan completed for session ${id}, fetching alerts...`);
            
            const alertsResp = await makeZapApiCall<ZapAlertsResponse>('/JSON/core/view/alerts/', { baseurl: url });

            if (!alertsResp.alerts) {
              console.error(`Invalid response format for session ${id}:`, JSON.stringify(alertsResp, null, 2));
              throw new Error('Invalid response format from ZAP API');
            }

            console.log(`Fetched ${alertsResp.alerts.length} alerts for session ${id}`);

            // Create a Map to store unique alerts based on alert name
            const uniqueAlertsMap = new Map();
            
            // Group alerts by name and collect URLs
            alertsResp.alerts.forEach((alert: any) => {
              const key = alert.name;
              if (!uniqueAlertsMap.has(key)) {
                uniqueAlertsMap.set(key, {
                  ...alert,
                  urls: [alert.url]
                });
              } else {
                const existingAlert = uniqueAlertsMap.get(key);
                if (!existingAlert.urls.includes(alert.url)) {
                  existingAlert.urls.push(alert.url);
                }
              }
            });

            const uniqueAlerts = Array.from(uniqueAlertsMap.values());
            console.log(`Found ${uniqueAlerts.length} unique alerts after grouping by name`);

            // Add non-technical descriptions to each unique alert
            console.log('Starting translation of unique alerts...');
            
            const alertsWithTranslations = await Promise.all(
              uniqueAlerts.map(async (alert: any, index: number) => {
                try {
                  console.log(`Translating alert ${index + 1}/${uniqueAlerts.length}...`);
                  const nonTechnicalDescription = await translateAlertToNonTechnical(alert);
                  const processedAlert = {
                    ...alert,
                    nonTechnicalDescription,
                    risk: alert.risk || 'Unknown',
                    confidence: alert.confidence || 'Unknown',
                    tags: alert.tags || {},
                    cweid: alert.cweid || '',
                    wascid: alert.wascid || '',
                    solution: alert.solution || '',
                    reference: alert.reference || '',
                    description: alert.description || '',
                    urls: alert.urls || []
                  };

                  // Log the processed alert with translation
                  console.log(`Processed alert ${index + 1} with translation:`, {
                    name: processedAlert.name,
                    hasTranslation: !!processedAlert.nonTechnicalDescription,
                    translationLength: processedAlert.nonTechnicalDescription?.length
                  });

                  return processedAlert;
                } catch (translationError) {
                  console.error(`Error processing alert ${index + 1} for session ${id}:`, translationError);
                  return {
                    ...alert,
                    nonTechnicalDescription: alert.description, // Fallback to original description
                    risk: alert.risk || 'Unknown',
                    confidence: alert.confidence || 'Unknown',
                    tags: alert.tags || {},
                    cweid: alert.cweid || '',
                    wascid: alert.wascid || '',
                    solution: alert.solution || '',
                    reference: alert.reference || '',
                    description: alert.description || '',
                    urls: alert.urls || []
                  };
                }
              })
            );

            if (alertsWithTranslations && alertsWithTranslations.length > 0) {
              console.log(`Saving ${alertsWithTranslations.length} alerts with translations to database...`);
              await prisma.scanSession.update({
                where: { id },
                data: { 
                  activeResults: alertsWithTranslations as any
                },
              });
              console.log(`Successfully saved ${alertsWithTranslations.length} alerts for session ${id}`);
            } else {
              console.error(`No alerts were processed successfully for session ${id}`);
              await prisma.scanSession.update({
                where: { id },
                data: { 
                  activeResults: [] as any,
                  activeStatus: 100
                },
              });
            }
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