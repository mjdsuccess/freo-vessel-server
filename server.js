// Freo Port Server - v2
const express = require('express');
const cors = require('cors');
const https = require('https');

const app = express();
app.use(cors());
const PORT = process.env.PORT || 3000;

const BASE_URL = 'https://www3.fremantleports.com.au/vtmis';
const DASHBOARD_URL = `${BASE_URL}/dashb.ashx?db=fmp.public&btn=ExpectedMovements`;
const DATA_URL = `${BASE_URL}/services/wxdata.svc/GetDataX`;

const BROWSER_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'en-AU,en;q=0.9',
};

function httpGet(url, headers) {
  return new Promise((resolve, reject) => {
    const options = {
      headers: { ...BROWSER_HEADERS, ...headers },
    };
    https.get(url, options, (res) => {
      let data = '';
      const cookies = res.headers['set-cookie'] || [];
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ 
        status: res.statusCode, 
        body: data, 
        cookies 
      }));
    }).on('error', reject);
  });
}

function httpPost(url, body, headers) {
  return new Promise((resolve, reject) => {
    const bodyStr = JSON.stringify(body);
    const urlObj = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=UTF-8',
        'Content-Length': Buffer.byteLength(bodyStr),
        ...BROWSER_HEADERS,
        ...headers,
      },
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ 
        status: res.statusCode, 
        body: data 
      }));
    });
    req.on('error', reject);
    req.write(bodyStr);
    req.end();
  });
}

function extractStamp(html) {
  const match = html.match(/scope\.__stamp\s*=\s*'([^']+)'/);
  if (match) return match[1] + '\u000bfmp.public/main-view';
  return null;
}

function extractCookies(cookieArray) {
  return cookieArray
    .map(c => c.split(';')[0].trim())
    .filter(c => c.length > 0)
    .join('; ');
}

async function fetchVessels() {
  console.log('STEP 1: Loading dashboard...');
  const pageRes = await httpGet(DASHBOARD_URL);
  console.log('PAGE STATUS:', pageRes.status);

  if (pageRes.status !== 200) {
    throw new Error(`Dashboard returned ${pageRes.status}`);
  }

  const cookies = extractCookies(pageRes.cookies);
  console.log('COOKIES:', cookies.substring(0, 50) + '...');

  const stamp = extractStamp(pageRes.body);
  if (!stamp) {
    console.log('BODY PREVIEW:', pageRes.body.substring(0, 500));
    throw new Error('Could not extract stamp');
  }
  console.log('STAMP:', stamp.substring(0, 20) + '...');

  const now = new Date();
  const pad = n => String(n).padStart(2, '0');
  const from = `${now.getFullYear()}-${pad(now.getMonth()+1)}-${pad(now.getDate())}T00:00:00.000`;
  const toDate = new Date(now.getTime() + 28 * 24 * 60 * 60 * 1000);
  const to = `${toDate.getFullYear()}-${pad(toDate.getMonth()+1)}-${pad(toDate.getDate())}T23:59:59.000`;

  console.log('STEP 2: Fetching vessel data...');
  const dataRes = await httpPost(
    DATA_URL,
    {
      request: {
        requestID: `${now.getTime()}-1`,
        reportCode: 'FMP-WEB-0001',
        dataSource: null,
        filterName: null,
        parameters: [
          {
            '__type': 'ParameterValueDTO:#WebX.Core.DTO',
            sName: 'FROM_TIME',
            iValueType: 0,
            aoValues: [{ '__type': 'ValueItemDTO:#WebX.Core.DTO', Value: from }],
          },
          {
            '__type': 'ParameterValueDTO:#WebX.Core.DTO',
            sName: 'TO_TIME',
            iValueType: 0,
            aoValues: [{ '__type': 'ValueItemDTO:#WebX.Core.DTO', Value: to }],
          },
        ],
        metaVersion: 0,
        '_type': 'TGetDataXREQ:#WebX.Services',
        stamp: stamp,
      }
    },
    {
      'Cookie': cookies,
      'Origin': 'https://www3.fremantleports.com.au',
      'Referer': DASHBOARD_URL,
      'X-Requested-With': 'XMLHttpRequest',
    }
  );

  console.log('DATA STATUS:', dataRes.status);
  console.log('DATA PREVIEW:', dataRes.body.substring(0, 100));

  if (dataRes.status !== 200) {
    throw new Error(`Data request returned ${dataRes.status}: ${dataRes.body.substring(0, 200)}`);
  }

  return JSON.parse(dataRes.body);
}

// API ROUTE

// Visitor tracking
const visitorMap = {};
let visitorCount = 0;
const visitLog = [];

function getVisitorId(ip) {
  if (!visitorMap[ip]) {
    visitorCount++;
    visitorMap[ip] = `Visitor ${visitorCount}`;
  }
  return visitorMap[ip];
}

// API ROUTE

app.get('/vessels', async (req, res) => {

  // Log the visit
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const visitorId = getVisitorId(ip);
  const timestamp = new Date().toLocaleString('en-AU');
  const logEntry = { visitor: visitorId, time: timestamp };
  visitLog.push(logEntry);
  console.log(`${visitorId}: ${timestamp}`);

  try {
    const data = await fetchVessels();
    res.json({
      updated: new Date().toISOString(),
      data: data
    });
  } catch (err) {
    console.error('ERROR:', err.message);
    res.status(503).json({ error: err.message });
  }
});

// STATS PAGE
app.get('/stats', (req, res) => {
  const rows = visitLog.map(e =>
    `<tr><td>${e.visitor}</td><td>${e.time}</td></tr>`
  ).join('');

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Freo Port — Visitor Stats</title>
      <style>
        body { font-family: Arial, sans-serif; background: #003B6F; color: white; padding: 30px; }
        h1 { color: #E87722; }
        p { color: #B0C4DE; margin-bottom: 20px; }
        table { border-collapse: collapse; width: 100%; max-width: 600px; background: white; color: #333; border-radius: 8px; overflow: hidden; }
        th { background: #003B6F; color: white; padding: 10px 16px; text-align: left; }
        td { padding: 8px 16px; border-bottom: 1px solid #eee; }
        tr:last-child td { border-bottom: none; }
        tr:nth-child(even) td { background: #F5F7FA; }
        .count { font-size: 14px; color: #B0C4DE; margin-top: 16px; }
      </style>
    </head>
    <body>
      <h1>Freo Port — Visitor Log</h1>
      <p>Unique visitors: <b>${visitorCount}</b> &nbsp;|&nbsp; Total visits: <b>${visitLog.length}</b></p>
      <table>
        <tr><th>Visitor</th><th>Date &amp; Time</th></tr>
        ${rows || '<tr><td colspan="2">No visits recorded yet</td></tr>'}
      </table>
      <p class="count">Log clears when server restarts.</p>
    </body>
    </html>
  `);
});


// HEALTH CHECK
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// In-memory availability storage (clears on server restart)
let availabilityData = {};
let availabilityWeekStart = null;

function getNextMondayDate() {
  const now = new Date();
  const day = now.getDay();
  const daysToMon = day === 0 ? 1 : (8 - day) % 7 || 7;
  const mon = new Date(now);
  mon.setDate(now.getDate() + daysToMon);
  mon.setHours(0, 0, 0, 0);
  return mon.toISOString().split('T')[0];
}

function checkAndClearAvailability() {
  const now = new Date();
  // Clear at 1am Sunday (day 0)
  if (now.getDay() === 0 && now.getHours() >= 1) {
    const thisWeek = getNextMondayDate();
    if (availabilityWeekStart !== thisWeek) {
      console.log('Auto-clearing availability for new week');
      console.log(`Auto-clearing availability for new week at ${new Date().toLocaleString('en-AU')}`);
    // For testing purposes
      console.log('Auto-clearing availability for new week');
      availabilityData = {};
      availabilityWeekStart = thisWeek;
    }
  }
}

// GET /availability - return all volunteer entries
app.get('/availability', (req, res) => {
  checkAndClearAvailability();
  res.json({
    weekStart: getNextMondayDate(),
    volunteers: availabilityData
  });
});

// POST /availability - save or update a volunteer entry
app.use(express.json());
app.post('/availability', (req, res) => {
  checkAndClearAvailability();
  const { name, availability } = req.body;
  if (!name || !availability) {
    return res.status(400).json({ error: 'name and availability required' });
  }
  availabilityData[name] = availability;
  console.log(`Availability saved for: ${name}`);
  res.json({ success: true, name, weekStart: getNextMondayDate() });
});

// DELETE /availability/:name - remove a volunteer entry
app.delete('/availability/:name', (req, res) => {
  checkAndClearAvailability();
  const name = decodeURIComponent(req.params.name);
  delete availabilityData[name];
  console.log(`Availability removed for: ${name}`);
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
