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
            
            let retryCount = 0;
            const maxRetries = 3;
            let alertsWithTranslations = null;

            while (retryCount < maxRetries) {
              try {
                console.log(`Attempting to fetch alerts from ZAP API (attempt ${retryCount + 1}/${maxRetries})...`);
                const alertsResp = await axios.get(`${ZAP_API_BASE}/JSON/core/view/alerts/`, {
                  params: { baseurl: url, apikey: ZAP_API_KEY },
                });

                if (!alertsResp.data || !alertsResp.data.alerts) {
                  console.error(`Invalid response format for session ${id}:`, JSON.stringify(alertsResp.data, null, 2));
                  throw new Error('Invalid response format from ZAP API');
                }

                console.log(`Fetched ${alertsResp.data.alerts.length} alerts for session ${id}`);

                // Add non-technical descriptions to each alert
                console.log('Starting translation of alerts...');
                alertsWithTranslations = await Promise.all(
                  alertsResp.data.alerts.map(async (alert: any, index: number) => {
                    try {
                      console.log(`Translating alert ${index + 1}/${alertsResp.data.alerts.length}...`);
                      const nonTechnicalDescription = await translateAlertToNonTechnical(alert);
                      return {
                        ...alert,
                        nonTechnicalDescription
                      };
                    } catch (translationError) {
                      console.error(`Error translating alert ${index + 1} for session ${id}:`, translationError);
                      // Return original alert without translation
                      return alert;
                    }
                  })
                );

                if (alertsWithTranslations && alertsWithTranslations.length > 0) {
                  console.log(`Successfully processed ${alertsWithTranslations.length} alerts`);
                  break; // Successfully got results, exit retry loop
                } else {
                  console.error('No alerts were processed successfully');
                  throw new Error('No alerts processed');
                }
              } catch (err: any) {
                console.error(`Error in alert processing for session ${id} (attempt ${retryCount + 1}/${maxRetries}):`, {
                  error: err.message,
                  stack: err.stack,
                  url,
                  activeId
                });
                retryCount++;
                if (retryCount < maxRetries) {
                  console.log(`Waiting ${retryDelay}ms before retry...`);
                  await new Promise(resolve => setTimeout(resolve, retryDelay));
                }
              }
            }

            if (alertsWithTranslations && alertsWithTranslations.length > 0) {
              await prisma.scanSession.update({
                where: { id },
                data: { 
                  activeResults: alertsWithTranslations as any
                },
              });
              console.log(`Successfully saved ${alertsWithTranslations.length} alerts for session ${id}`);
            } else {
              console.error(`Failed to fetch valid alerts for session ${id} after ${maxRetries} attempts`);
              // Update the session to indicate the failure
              await prisma.scanSession.update({
                where: { id },
                data: { 
                  activeResults: [] as any, // Set empty array instead of null
                  activeStatus: 100 // Keep status at 100
                },
              });
            }
          }
        } else if (activeId && activeStatus === 100 && !session.activeResults) {
          // Handle case where status is 100 but results are null
          console.log(`Found session ${id} with activeStatus 100 but null results. Fetching alerts...`);
          
          let retryCount = 0;
          const maxRetries = 3;
          let alertsWithTranslations = null;

          while (retryCount < maxRetries) {
            try {
              const alertsResp = await axios.get(`${ZAP_API_BASE}/JSON/core/view/alerts/`, {
                params: { baseurl: url, apikey: ZAP_API_KEY },
              });

              if (!alertsResp.data || !alertsResp.data.alerts) {
                console.error(`Invalid response format for session ${id}:`, alertsResp.data);
                throw new Error('Invalid response format from ZAP API');
              }

              console.log(`Fetched ${alertsResp.data.alerts.length} alerts for session ${id}`);

              alertsWithTranslations = await Promise.all(
                alertsResp.data.alerts.map(async (alert: any) => {
                  try {
                    const nonTechnicalDescription = await translateAlertToNonTechnical(alert);
                    return {
                      ...alert,
                      nonTechnicalDescription
                    };
                  } catch (translationError) {
                    console.error(`Error translating alert for session ${id}:`, translationError);
                    // Return original alert without translation
                    return alert;
                  }
                })
              );

              if (alertsWithTranslations && alertsWithTranslations.length > 0) {
                break;
              }
            } catch (err: any) {
              console.error(`Error fetching alerts for session ${id} (attempt ${retryCount + 1}/${maxRetries}):`, err);
              retryCount++;
              if (retryCount < maxRetries) {
                console.log(`Waiting ${retryDelay}ms before retry...`);
                await new Promise(resolve => setTimeout(resolve, retryDelay));
              }
            }
          }

          if (alertsWithTranslations && alertsWithTranslations.length > 0) {
            await prisma.scanSession.update({
              where: { id },
              data: { 
                activeResults: alertsWithTranslations as any
              },
            });
            console.log(`Successfully saved ${alertsWithTranslations.length} alerts for session ${id}`);
          } else {
            console.error(`Failed to fetch valid alerts for session ${id} after ${maxRetries} attempts`);
            await prisma.scanSession.update({
              where: { id },
              data: { 
                activeResults: [] as any
              },
            });
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
