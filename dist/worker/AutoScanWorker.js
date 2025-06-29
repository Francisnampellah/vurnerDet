"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const axios_1 = __importDefault(require("axios"));
const client_1 = require("@prisma/client");
const dotenv_1 = __importDefault(require("dotenv"));
// Load environment variables
dotenv_1.default.config();
const prisma = new client_1.PrismaClient();
const ZAP_API_BASE = 'http://zap:8080';
const ZAP_API_KEY = '';
const HUGGINGFACE_API_KEY = process.env.HUGG_FACE_API || "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";
const HUGGINGFACE_API_URL = 'https://router.huggingface.co/novita/v3/openai/chat/completions';
// Enhanced configuration for API calls
const API_CONFIG = {
    timeout: 30000, // 30 seconds timeout
    headers: {
        'Content-Type': 'application/json',
    },
    maxRedirects: 5,
    validateStatus: (status) => status >= 200 && status < 500 // Accept all responses except 5xx errors
};
// Rate limiting and retry configuration
const RATE_LIMIT_DELAY = 2000; // 2 seconds delay between API calls
const MAX_RETRIES = 3;
const INITIAL_RETRY_DELAY = 1000; // 1 second
// Worker configuration
const SCAN_INTERVAL_MS = 10000; // 10 seconds
const MAX_DB_RETRIES = 10;
const DB_RETRY_DELAY = 5000; // 5 seconds
// Helper function for exponential backoff
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));
// Helper function to check if target is reachable
async function isTargetReachable(url) {
    try {
        console.log(`Checking if target ${url} is reachable...`);
        const response = await axios_1.default.get(url, {
            timeout: 10000,
            validateStatus: (status) => status < 500 // Accept any response that's not a server error
        });
        console.log(`Target ${url} is reachable (status: ${response.status})`);
        return true;
    }
    catch (error) {
        console.error(`Target ${url} is not reachable:`, error.message);
        return false;
    }
}
// Helper function for making API calls with retry logic
async function makeZapApiCall(endpoint, params, retryCount = 0) {
    try {
        await delay(RATE_LIMIT_DELAY);
        console.log(`Making ZAP API call to ${endpoint} with params:`, params);
        const response = await axios_1.default.get(`${ZAP_API_BASE}${endpoint}`, {
            params: { ...params, apikey: ZAP_API_KEY },
            ...API_CONFIG
        });
        console.log(`ZAP API call successful: ${endpoint}`);
        return response.data;
    }
    catch (error) {
        console.error(`ZAP API call failed: ${endpoint}`, {
            error: error.message,
            status: error.response?.status,
            data: error.response?.data
        });
        if (retryCount < MAX_RETRIES) {
            const backoffDelay = INITIAL_RETRY_DELAY * Math.pow(2, retryCount);
            console.log(`Retrying ZAP API call in ${backoffDelay}ms (attempt ${retryCount + 1}/${MAX_RETRIES})`);
            await delay(backoffDelay);
            return makeZapApiCall(endpoint, params, retryCount + 1);
        }
        throw new Error(`ZAP API call failed after ${MAX_RETRIES} retries: ${error.message}`);
    }
}
async function waitForDatabase(retries = MAX_DB_RETRIES) {
    for (let i = 0; i < retries; i++) {
        try {
            console.log(`Attempting to connect to database (attempt ${i + 1}/${retries})...`);
            await prisma.$connect();
            console.log('✅ Successfully connected to database');
            return;
        }
        catch (err) {
            console.error(`❌ Database connection attempt ${i + 1} failed:`, err.message);
            if (i < retries - 1) {
                console.log(`⏳ Waiting ${DB_RETRY_DELAY}ms before next attempt...`);
                await delay(DB_RETRY_DELAY);
            }
        }
    }
    throw new Error('Failed to connect to database after maximum retries');
}
async function translateAlertToNonTechnical(alert) {
    try {
        console.log(`🔄 Making translation request for alert: ${alert.name}`);
        const response = await axios_1.default.post(HUGGINGFACE_API_URL, {
            model: "deepseek/deepseek-v3-0324",
            messages: [
                {
                    role: "system",
                    content: "You are a helpful assistant that explains security alerts in non-technical, plain English. Keep your explanations concise (maximum 100 words), clear, and properly formatted as plain text without markdown or special formatting."
                },
                {
                    role: "user",
                    content: `Please explain this security alert in everyday language so a non-technical person can understand it. Keep it under 100 words and use plain text formatting: ${alert.description}`
                }
            ],
            temperature: 0.7,
            max_tokens: 200
        }, {
            headers: {
                'Authorization': `Bearer ${HUGGINGFACE_API_KEY}`,
                'Content-Type': 'application/json',
            },
            timeout: 30000, // 30 second timeout for translation
        });
        if (!response.data || !response.data.choices || !response.data.choices[0]?.message?.content) {
            console.error('❌ Invalid response format from Hugging Face API:', JSON.stringify(response.data));
            return alert.description;
        }
        const translatedText = response.data.choices[0].message.content.trim();
        // If the translation is too similar to the original, try a different approach
        if (translatedText.length > alert.description.length * 0.8 &&
            translatedText.length < alert.description.length * 1.2) {
            console.log('🔄 Translation too similar to original, trying alternative prompt...');
            // Try a more direct prompt
            const retryResponse = await axios_1.default.post(HUGGINGFACE_API_URL, {
                model: "deepseek/deepseek-v3-0324",
                messages: [
                    {
                        role: "system",
                        content: "You are a helpful assistant that explains security alerts in non-technical, plain English. Keep your explanations concise (maximum 100 words), clear, and properly formatted as plain text without markdown or special formatting."
                    },
                    {
                        role: "user",
                        content: `Explain this security issue to someone who knows nothing about computers. Use very simple language, avoid all technical terms, keep it under 100 words, and use plain text formatting: ${alert.description}`
                    }
                ],
                temperature: 0.7,
                max_tokens: 200
            }, {
                headers: {
                    'Authorization': `Bearer ${HUGGINGFACE_API_KEY}`,
                    'Content-Type': 'application/json',
                },
                timeout: 30000,
            });
            if (retryResponse.data?.choices?.[0]?.message?.content) {
                const retryText = retryResponse.data.choices[0].message.content.trim();
                if (retryText && retryText !== translatedText) {
                    console.log(`✅ Retry successful with different explanation. Original: "${alert.description.substring(0, 100)}..." -> New translation: "${retryText.substring(0, 100)}..."`);
                    return retryText;
                }
            }
        }
        console.log(`✅ Successfully translated alert. Original: "${alert.description.substring(0, 100)}..." -> Translated: "${translatedText.substring(0, 100)}..."`);
        return translatedText;
    }
    catch (error) {
        console.error('❌ Error translating alert:', {
            error: error.message,
            response: error.response?.data,
            alertName: alert.name
        });
        return alert.description; // Return original description if translation fails
    }
}
// Helper function to add URL to ZAP context
async function addUrlToZapContext(url) {
    try {
        console.log(`🔗 Adding URL to ZAP context: ${url}`);
        // Add the URL to ZAP's context
        await makeZapApiCall('/JSON/core/action/accessUrl/', { url });
        // Wait a moment for ZAP to process
        await delay(2000);
        console.log(`✅ URL added to ZAP context: ${url}`);
    }
    catch (error) {
        console.error(`❌ Failed to add URL to ZAP context: ${url}`, error.message);
        // If it's a DNS or network error, log it but don't throw
        if (error.message.includes('500') || error.message.includes('Internal Error')) {
            console.log(`⚠️ ZAP internal error for ${url}, this might be due to DNS issues. Continuing...`);
            return; // Don't throw, let the scan continue
        }
        throw error;
    }
}
// Helper function to start active scan with proper context
async function startActiveScan(url) {
    try {
        console.log(`🚀 Starting active scan for URL: ${url}`);
        try {
            await addUrlToZapContext(url);
            console.log(`✅ Context setup success for ${url}, and continuing with scan...`);
        }
        catch (contextError) {
            console.log(`⚠️ Context setup failed for ${url}, but continuing with scan...`);
        }
        // Then start the active scan
        const activeResp = await makeZapApiCall('/JSON/ascan/action/scan/', {
            url,
            recurse: true
        });
        const objectAsString = JSON.stringify(activeResp);
        console.log("+++++++++++++++++++++++++++++++++++++++++++");
        console.log(`✅ Active scan of ${url} started successfully with ID: ${objectAsString}`);
        console.log("+++++++++++++++++++++++++++++++++++++++++++");
        return activeResp.scan;
    }
    catch (error) {
        if (error.message.includes('URL_NOT_FOUND')) {
            console.log(`🔄 URL_NOT_FOUND error, retrying with context setup...`);
            // Try adding URL to context again and retry
            try {
                await addUrlToZapContext(url);
                await delay(3000); // Wait longer for context to be established
            }
            catch (contextError) {
                console.log(`⚠️ Context setup failed on retry, but continuing...`);
            }
            const retryResp = await makeZapApiCall('/JSON/ascan/action/scan/', {
                url,
                recurse: true,
                inScopeOnly: false
            });
            console.log(`✅ Active scan started on retry with ID: ${retryResp.scan}`);
            return retryResp.scan;
        }
        // Handle other errors
        if (error.message.includes('500') || error.message.includes('Internal Error')) {
            console.error(`❌ ZAP internal error for ${url}. This might be due to DNS or network issues.`);
            throw new Error(`ZAP internal error: ${error.message}`);
        }
        throw error;
    }
}
// Helper function to check if ZAP is ready
async function isZapReady() {
    try {
        console.log('🔍 Checking if ZAP is ready...');
        const response = await axios_1.default.get(`${ZAP_API_BASE}/JSON/core/view/version/`, {
            timeout: 10000,
            validateStatus: (status) => status < 500
        });
        if (response.status === 200 && response.data) {
            console.log(`✅ ZAP is ready (version: ${response.data.version})`);
            return true;
        }
        console.log(`⚠️ ZAP responded but not ready (status: ${response.status})`);
        return false;
    }
    catch (error) {
        console.error('❌ ZAP is not ready:', error.message);
        return false;
    }
}
// Helper function to wait for ZAP to be ready
async function waitForZap(maxRetries = 10) {
    for (let i = 0; i < maxRetries; i++) {
        if (await isZapReady()) {
            return;
        }
        console.log(`⏳ Waiting for ZAP to be ready (attempt ${i + 1}/${maxRetries})...`);
        await delay(5000); // Wait 5 seconds between attempts
    }
    throw new Error('ZAP failed to become ready after maximum retries');
}
async function updateScans() {
    console.log('🔄 Starting scan update cycle...');
    try {
        const sessions = await prisma.scanSession.findMany({
            where: {
                OR: [
                    { spiderStatus: { lt: 100 } },
                    { activeStatus: { lt: 100 } }
                ]
            }
        });
        console.log(`📊 Found ${sessions.length} active scan sessions`);
        if (sessions.length === 0) {
            console.log('✅ No active scans to process');
            return;
        }
        for (const session of sessions) {
            const { id, spiderId, spiderStatus, activeId, activeStatus, url } = session;
            console.log(session);
            console.log(`🔍 Processing session ${id} for URL: ${url}`);
            try {
                // Check if target is reachable before proceeding
                const isReachable = await isTargetReachable(url);
                if (!isReachable) {
                    console.error(`❌ Target ${url} is not reachable, skipping scan session ${id}`);
                    continue;
                }
                // Update Spider Status
                if (spiderId && spiderStatus < 100) {
                    console.log(`🕷️ Checking spider status for session ${id} (spiderId: ${spiderId})`);
                    const spiderStatusResp = await makeZapApiCall('/JSON/spider/view/status/', { scanId: spiderId });
                    const newStatus = parseInt(spiderStatusResp.status);
                    console.log(`🕷️ Spider status for session ${id}: ${newStatus}%`);
                    await prisma.scanSession.update({
                        where: { id },
                        data: { spiderStatus: newStatus }
                    });
                    if (newStatus === 100) {
                        console.log(`✅ Spider scan completed for session ${id}, fetching results...`);
                        const spiderResultsResp = await makeZapApiCall('/JSON/spider/view/results/', { scanId: spiderId });
                        await prisma.scanSession.update({
                            where: { id },
                            data: {
                                spiderResults: spiderResultsResp.results
                            },
                        });
                        console.log(`✅ Spider results saved for session ${id}`);
                    }
                }
                // If spider is done and active scan hasn't started, start active scan
                if (spiderId && spiderStatus === 100 && !activeId) {
                    console.log(`🟢 Spider complete and no active scan started for session ${id}, starting active scan...`);
                    try {
                        const activeScanId = await startActiveScan(url);
                        await prisma.scanSession.update({
                            where: { id },
                            data: {
                                activeId: activeScanId,
                                activeStatus: 0
                            },
                        });
                        console.log(`✅ Active scan started for session ${id} with ID: ${activeScanId}`);
                    }
                    catch (activeScanError) {
                        console.error(`❌ Failed to start active scan for session ${id}:`, activeScanError.message);
                        await prisma.scanSession.update({
                            where: { id },
                            data: {
                                activeStatus: -1,
                                activeResults: { error: activeScanError.message }
                            },
                        });
                    }
                }
                // Update Active Status
                if (activeId && activeStatus < 100) {
                    console.log(`🔍 Checking active scan status for session ${id} (activeId: ${activeId})`);
                    const activeStatusResp = await makeZapApiCall('/JSON/ascan/view/status/', { scanId: activeId });
                    const newStatus = parseInt(activeStatusResp.status);
                    console.log(`🔍 Active scan status for session ${id}: ${newStatus}%`);
                    await prisma.scanSession.update({
                        where: { id },
                        data: { activeStatus: newStatus }
                    });
                    if (newStatus === 100) {
                        console.log(`✅ Active scan completed for session ${id}, fetching alerts...`);
                        const alertsResp = await makeZapApiCall('/JSON/core/view/alerts/', { baseurl: url });
                        if (!alertsResp.alerts) {
                            console.error(`❌ Invalid response format for session ${id}:`, JSON.stringify(alertsResp, null, 2));
                            throw new Error('Invalid response format from ZAP API');
                        }
                        console.log(`📊 Fetched ${alertsResp.alerts.length} alerts for session ${id}`);
                        // Create a Map to store unique alerts based on alert name
                        const uniqueAlertsMap = new Map();
                        // Group alerts by name and collect URLs
                        alertsResp.alerts.forEach((alert) => {
                            const key = alert.name;
                            if (!uniqueAlertsMap.has(key)) {
                                uniqueAlertsMap.set(key, {
                                    ...alert,
                                    urls: [alert.url]
                                });
                            }
                            else {
                                const existingAlert = uniqueAlertsMap.get(key);
                                if (!existingAlert.urls.includes(alert.url)) {
                                    existingAlert.urls.push(alert.url);
                                }
                            }
                        });
                        const uniqueAlerts = Array.from(uniqueAlertsMap.values());
                        console.log(`📊 Found ${uniqueAlerts.length} unique alerts after grouping by name`);
                        // Add non-technical descriptions to each unique alert
                        console.log('🔄 Starting translation of unique alerts...');
                        const alertsWithTranslations = await Promise.all(uniqueAlerts.map(async (alert, index) => {
                            try {
                                console.log(`🔄 Translating alert ${index + 1}/${uniqueAlerts.length}...`);
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
                                console.log(`✅ Processed alert ${index + 1} with translation:`, {
                                    name: processedAlert.name,
                                    hasTranslation: !!processedAlert.nonTechnicalDescription,
                                    translationLength: processedAlert.nonTechnicalDescription?.length
                                });
                                return processedAlert;
                            }
                            catch (translationError) {
                                console.error(`❌ Error processing alert ${index + 1} for session ${id}:`, translationError);
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
                        }));
                        if (alertsWithTranslations && alertsWithTranslations.length > 0) {
                            console.log(`💾 Saving ${alertsWithTranslations.length} alerts with translations to database...`);
                            await prisma.scanSession.update({
                                where: { id },
                                data: {
                                    activeResults: alertsWithTranslations
                                },
                            });
                            console.log(`✅ Successfully saved ${alertsWithTranslations.length} alerts for session ${id}`);
                        }
                        else {
                            console.error(`❌ No alerts were processed successfully for session ${id}`);
                            await prisma.scanSession.update({
                                where: { id },
                                data: {
                                    activeResults: [],
                                    activeStatus: 100
                                },
                            });
                        }
                    }
                }
            }
            catch (err) {
                console.error(`❌ Error processing session ${id}:`, {
                    error: err.message,
                    stack: err.stack,
                    url,
                    spiderId,
                    activeId
                });
            }
        }
    }
    catch (err) {
        console.error('❌ Critical error in updateScans:', {
            error: err.message,
            stack: err.stack
        });
    }
    console.log('✅ Completed scan update cycle');
}
// Graceful shutdown handling
process.on('SIGINT', async () => {
    console.log('🛑 Received SIGINT, shutting down gracefully...');
    await prisma.$disconnect();
    process.exit(0);
});
process.on('SIGTERM', async () => {
    console.log('🛑 Received SIGTERM, shutting down gracefully...');
    await prisma.$disconnect();
    process.exit(0);
});
// Error handling for uncaught exceptions
process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error);
    process.exit(1);
});
process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
});
// Main worker function
async function startWorker() {
    try {
        console.log('🚀 Starting AutoScanWorker...');
        // Wait for database connection
        await waitForDatabase();
        console.log('✅ Database connection established, waiting for ZAP...');
        // Wait for ZAP to be ready
        await waitForZap();
        console.log('✅ ZAP is ready, starting worker...');
        // Initial run
        await updateScans();
        // Set up interval for periodic updates
        console.log(`⏰ Setting up scan interval (${SCAN_INTERVAL_MS}ms)...`);
        setInterval(updateScans, SCAN_INTERVAL_MS);
        console.log('✅ AutoScanWorker is now running and monitoring scan sessions');
    }
    catch (error) {
        console.error('❌ Fatal error starting worker:', error);
        process.exit(1);
    }
}
// Start the worker
startWorker().catch(err => {
    console.error('❌ Failed to start worker:', err);
    process.exit(1);
});
