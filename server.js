require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'wellspring-healthcare-production-secret-token-2026';

// Security & reverse-proxy trust for cloud platforms (Render, Railway, Fly.io, etc.)
app.set('trust proxy', 1);
app.disable('x-powered-by');

// Flexible & secure CORS Configuration
const rawFrontendUrl = process.env.FRONTEND_URL || '';
const frontendOrigins = rawFrontendUrl
  .split(',')
  .map(url => url.trim().replace(/\/$/, ''))
  .filter(Boolean);

const defaultOrigins = [
  'http://localhost:5173',
  'http://localhost:3000',
  'http://127.0.0.1:5173',
  'http://127.0.0.1:3000'
];

const allowedOrigins = [...new Set([...defaultOrigins, ...frontendOrigins])];

app.use(cors({
  origin: function (origin, callback) {
    // Allow non-browser requests (e.g. mobile apps, curl, uptime/health check monitors)
    if (!origin) return callback(null, true);

    // If FRONTEND_URL is wildcard '*' allow all origins
    if (rawFrontendUrl.trim() === '*') return callback(null, true);

    const cleanOrigin = origin.replace(/\/$/, '');
    if (allowedOrigins.includes(cleanOrigin)) {
      return callback(null, true);
    }

    console.warn(`[CORS Blocked] Origin: ${origin}. Allowed: ${allowedOrigins.join(', ')}`);
    return callback(new Error(`Not allowed by CORS: ${origin}`));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Route compatibility middleware: Auto-prefix '/api' if frontend omitted it
// (e.g. calls to /admin/login automatically route to /api/admin/login)
app.use((req, res, next) => {
  if (!req.url.startsWith('/api') && req.url !== '/' && !req.url.startsWith('/health')) {
    req.url = '/api' + req.url;
  }
  next();
});

// ----------------------------------------------------------------------------
// Rate Limiter Engine (Sliding Window in Pure Node.js - No External Dependencies)
// ----------------------------------------------------------------------------
function createRateLimiter({ windowMs, maxRequests, message }) {
  const hits = new Map();

  setInterval(() => {
    const now = Date.now();
    for (const [ip, data] of hits.entries()) {
      if (now > data.resetTime) hits.delete(ip);
    }
  }, 180000).unref(); // Auto-clean expired records every 3 minutes

  return function (req, res, next) {
    const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const record = hits.get(ip);

    if (!record || now > record.resetTime) {
      hits.set(ip, { count: 1, resetTime: now + windowMs });
      return next();
    }

    if (record.count >= maxRequests) {
      const retryAfter = Math.ceil((record.resetTime - now) / 1000);
      res.setHeader('Retry-After', retryAfter);
      return res.status(429).json({
        error: message || 'Too many requests. Please try again later.',
        retryAfter
      });
    }

    record.count++;
    next();
  };
}

// 1. Strict rate limiter for Login endpoints (15 attempts per 10 minutes)
const loginLimiter = createRateLimiter({
  windowMs: 10 * 60 * 1000,
  maxRequests: 15,
  message: 'Too many login attempts from this IP. Please wait 10 minutes before retrying.'
});

// 2. Rate limiter for Dialog SMS gateway (10 SMS dispatches per 5 minutes per IP)
const smsLimiter = createRateLimiter({
  windowMs: 5 * 60 * 1000,
  maxRequests: 10,
  message: 'SMS rate limit reached. Please wait a few minutes before sending another SMS receipt.'
});

// 3. General DDoS and scraper protective limiter (400 requests/minute)
const generalLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: 400,
  message: 'Traffic limit reached. Please slow down.'
});

app.use(generalLimiter);

// ----------------------------------------------------------------------------
// Cryptographic JWT Engine (HS256 with Timing-Safe Verification)
// ----------------------------------------------------------------------------
function signJWT(payload, expiresInSeconds = 86400) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const exp = Math.floor(Date.now() / 1000) + expiresInSeconds;
  const fullPayload = { ...payload, exp, iat: Math.floor(Date.now() / 1000) };

  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(fullPayload)).toString('base64url');

  const signature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64url');

  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

function verifyJWT(token) {
  try {
    if (!token || typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;

    const expectedSignature = crypto
      .createHmac('sha256', JWT_SECRET)
      .update(`${headerB64}.${payloadB64}`)
      .digest('base64url');

    const sigBuffer = Buffer.from(signatureB64);
    const expectedBuffer = Buffer.from(expectedSignature);

    if (sigBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
      return null;
    }

    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));

    // Check expiration
    if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

// Authentication & Role-Based Authorization Middleware
function requireAuth(allowedRoles = []) {
  return (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;

    if (!token) {
      return res.status(401).json({ error: 'Unauthorized: Authentication token required.' });
    }

    const user = verifyJWT(token);
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized: Session has expired or is invalid. Please log in again.' });
    }

    // Role-based check (ADMIN has universal superadmin access to all routes)
    if (allowedRoles.length > 0 && !allowedRoles.includes(user.role) && user.role !== 'ADMIN') {
      return res.status(403).json({ error: `Forbidden: Role '${user.role}' is not authorized for this resource.` });
    }

    req.user = user;
    next();
  };
}

// Supabase environment variable validation
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.warn('⚠️ WARNING: SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY environment variables are missing!');
}

// Initialize Supabase with SERVICE_ROLE key
const supabase = createClient(
  supabaseUrl || 'https://placeholder.supabase.co',
  supabaseKey || 'placeholder-key'
);

// ----------------------------------------------------------------------------
// Helper Functions (With Concurrency Auto-Retry - P2)
// ----------------------------------------------------------------------------

// Always get current YYYY-MM-DD in Sri Lanka Time (UTC+5:30), even on cloud servers (UTC)
function getSriLankaTodayRange() {
  const slDateStr = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Colombo',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).format(new Date());

  return {
    dateStr: slDateStr,
    startISO: `${slDateStr}T00:00:00.000+05:30`,
    endISO: `${slDateStr}T23:59:59.999+05:30`
  };
}

// Strict YYYY-MM-DD calendar date validation (leap-year safe, prevents MM/DD swaps)
function isValidIsoDate(dateStr) {
  if (!dateStr || typeof dateStr !== 'string') return false;
  const match = dateStr.trim().match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return false;
  const year = parseInt(match[1], 10);
  const month = parseInt(match[2], 10);
  const day = parseInt(match[3], 10);
  if (year < 1850 || year > 2100 || month < 1 || month > 12) return false;
  let maxDay = 31;
  if (month === 2) {
    const isLeap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
    maxDay = isLeap ? 29 : 28;
  } else if ([4, 6, 9, 11].includes(month)) {
    maxDay = 30;
  }
  return day >= 1 && day <= maxDay;
}

// Safely get next ID for legacy tables without auto-increment
async function getNextId(tableName) {
  const { data, error } = await supabase
    .from(tableName)
    .select('id')
    .order('id', { ascending: false })
    .limit(1);

  if (error) throw error;
  return data && data.length > 0 ? Number(data[0].id) + 1 : 1;
}

// Priority 2: Concurrent-Safe Insert with automatic conflict retry on duplicate ID (error 23505)
async function safeInsertWithId(tableName, recordData, maxRetries = 5) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const nextId = await getNextId(tableName);
      const payload = { ...recordData, id: nextId };

      const { data, error } = await supabase
        .from(tableName)
        .insert([payload])
        .select()
        .single();

      if (error) {
        // PostgreSQL unique violation error code: 23505
        if (error.code === '23505' && attempt < maxRetries) {
          console.warn(`[Concurrency Retry] ID collision in table '${tableName}' on ID ${nextId}. Retrying attempt ${attempt + 1}...`);
          // Random jitter between 15ms - 55ms prevents repeated lockstep collision
          await new Promise(resolve => setTimeout(resolve, Math.floor(Math.random() * 40) + 15));
          continue;
        }
        throw error;
      }
      return data;
    } catch (err) {
      if (attempt >= maxRetries) throw err;
    }
  }
}

// Generates a clean, unique, collision-resistant Auth Code (e.g. WSP-7X8K)
function generateAuthCode() {
  const chars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
  let rand = '';
  for (let i = 0; i < 4; i++) {
    rand += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `WSP-${rand}`;
}

// ----------------------------------------------------------------------------
// Health Check & Root Endpoints (Required & Monitored by Render)
// ----------------------------------------------------------------------------
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString()
  });
});

app.get('/', (req, res) => {
  res.status(200).json({
    name: 'Wellspring Healthcare API',
    status: 'online',
    healthCheck: '/health',
    timestamp: new Date().toISOString()
  });
});

// ----------------------------------------------------------------------------
// SYSTEM ROUTE: Public Clinic Stats & Doctor Telemetry (Landing Page)
// ----------------------------------------------------------------------------
app.get('/api/system/public-stats', async (req, res) => {
  try {
    const { dateStr: todaySL, startISO, endISO } = getSriLankaTodayRange();

    const [queueRes, dispensedRes, doctorRes] = await Promise.all([
      supabase
        .from('ticket_master')
        .select('id', { count: 'exact', head: true })
        .eq('flag', 1)
        .eq('channeling_date', todaySL),
      supabase
        .from('pharmacy_bills')
        .select('id', { count: 'exact', head: true })
        .gte('created_at', startISO)
        .lte('created_at', endISO),
      supabase
        .from('doctors_master')
        .select('id')
        .eq('is_online', true)
        .eq('flag', 1)
        .limit(1)
    ]);

    res.json({
      queueCount: queueRes.count || 0,
      dispensedToday: dispensedRes.count || 0,
      isDoctorOnline: (doctorRes.data && doctorRes.data.length > 0) || false
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ROUTE 1: Encrypted Doctor Portal Login (Rate-Limited + Issues JWT)
// ============================================================================
app.post('/api/doctor/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }

    const { data: doctor, error } = await supabase
      .from('doctors_master')
      .select('id, name, specialty, reg_number, username, password, flag')
      .eq('username', username.trim())
      .eq('flag', 1)
      .single();

    if (error || !doctor) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    const isMatch = await bcrypt.compare(password, doctor.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    await supabase
      .from('doctors_master')
      .update({ is_online: true })
      .eq('id', doctor.id);

    const token = signJWT({
      id: doctor.id,
      name: doctor.name,
      username: doctor.username,
      role: 'DOCTOR'
    });

    res.json({
      id: doctor.id,
      name: doctor.name,
      specialty: doctor.specialty,
      reg_number: doctor.reg_number,
      username: doctor.username,
      role: 'DOCTOR',
      token
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ROUTE 2: Get Active Waiting Queue for Today (Strictly Today + Auto-Cleanup)
// Accessible by Waiting Room TV display and staff
// ============================================================================
app.get('/api/doctor/queue', async (req, res) => {
  try {
    const { dateStr: todaySL } = getSriLankaTodayRange();

    // Auto-Cleanup: Cancel any leftover flag=1 or flag=2 tickets from past dates
    await supabase
      .from('ticket_master')
      .update({ flag: 0 })
      .in('flag', [1, 2])
      .lt('channeling_date', todaySL);

    const { data: tickets, error: ticketErr } = await supabase
      .from('ticket_master')
      .select('*')
      .eq('flag', 1)
      .eq('channeling_date', todaySL)
      .order('id', { ascending: true })
      .limit(100);

    if (ticketErr) throw ticketErr;
    if (!tickets || tickets.length === 0) return res.json([]);

    const patientIds = [...new Set(tickets.map(t => t.patient_id).filter(Boolean))];
    const { data: patients, error: patErr } = await supabase
      .from('patients_master')
      .select('id, name, phone, birth_date, gender, married, common, reference, id_number, weight, height')
      .in('id', patientIds);

    if (patErr) throw patErr;

    const patientMap = {};
    (patients || []).forEach(p => { patientMap[p.id] = p; });

    const queue = tickets
      .map((t, idx) => ({
        ticket_id: t.id,
        daily_queue_no: idx + 1,
        ticket_number: t.number || idx + 1,
        channeling_date: t.channeling_date,
        insert_date: t.insert_date,
        patient: patientMap[t.patient_id] || null
      }))
      .filter(item => item.patient !== null);

    res.json(queue);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ROUTE 3: Server-Side Advanced Paginated Patient Search (Protected)
// ============================================================================
app.get('/api/patients/search', requireAuth(['DOCTOR', 'COUNTER']), async (req, res) => {
  try {
    const { name, nic, phone, dob, page: pageQuery } = req.query;
    const page = parseInt(pageQuery || '1', 10);
    const limit = 15;
    const offset = (page - 1) * limit;

    if (!name && !nic && !phone && !dob) {
      return res.json({ data: [], page, hasMore: false });
    }

    let queryBuilder = supabase
      .from('patients_master')
      .select('id, name, reference, common, id_number, phone, birth_date, gender, married, weight, height, last_visit_date');

    if (name) queryBuilder = queryBuilder.ilike('name', `%${name.trim()}%`);
    if (nic) queryBuilder = queryBuilder.ilike('id_number', `%${nic.trim()}%`);

    if (phone) {
      let cleanPhone = phone.trim();
      let noZero = cleanPhone.startsWith('0') ? cleanPhone.substring(1) : cleanPhone;
      let withZero = cleanPhone.startsWith('0') ? cleanPhone : '0' + cleanPhone;
      
      if (noZero.length > 0) {
        queryBuilder = queryBuilder.or(`phone.ilike.%${cleanPhone}%,phone.ilike.%${noZero}%,phone.ilike.%${withZero}%`);
      }
    }

    if (dob) {
      let cleanDob = dob.trim().replace(/\//g, '-');

      if (/^\d{4}$/.test(cleanDob)) {
        queryBuilder = queryBuilder.gte('birth_date', `${cleanDob}-01-01`).lte('birth_date', `${cleanDob}-12-31`);
      } else if (/^\d{4}-\d{2}$/.test(cleanDob)) {
        const [yearStr, monthStr] = cleanDob.split('-');
        const yearNum = parseInt(yearStr, 10);
        const monthNum = parseInt(monthStr, 10);
        if (monthNum < 1 || monthNum > 12) {
          return res.json({ data: [], page, hasMore: false });
        }
        const lastDay = new Date(Date.UTC(yearNum, monthNum, 0)).getUTCDate();
        queryBuilder = queryBuilder.gte('birth_date', `${cleanDob}-01`).lte('birth_date', `${cleanDob}-${String(lastDay).padStart(2, '0')}`);
      } else if (/^\d{4}-\d{2}-\d{2}$/.test(cleanDob)) {
        if (!isValidIsoDate(cleanDob)) {
          return res.json({ data: [], page, hasMore: false });
        }
        queryBuilder = queryBuilder.eq('birth_date', cleanDob);
      }
    }

    const { data, error } = await queryBuilder
      .order('id', { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) throw error;
    res.json({
      data: data || [],
      page,
      hasMore: (data || []).length === limit
    });
  } catch (err) {
    console.error("Search Error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ROUTE 4: Direct Walk-In Patient Registration (Protected + P2 Concurrency Safe)
// ============================================================================
app.post('/api/patients', requireAuth(['DOCTOR', 'COUNTER']), async (req, res) => {
  try {
    const { name, birth_date, phone, id_number, gender, married, common, weight, height } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Patient name is required' });
    }

    const cleanBirthDate = birth_date ? String(birth_date).trim() : null;
    if (cleanBirthDate && !isValidIsoDate(cleanBirthDate)) {
      return res.status(400).json({ error: 'Invalid Date of Birth format. Please use YYYY-MM-DD.' });
    }

    const now = new Date().toISOString();

    const newPatient = {
      name: name.trim(),
      birth_date: cleanBirthDate,
      phone: phone || '',
      id_number: id_number || '',
      reference: '',
      common: common || '',
      gender: gender ? Number(gender) : 1,
      married: married ? Number(married) : 0,
      weight: weight ? Number(weight) : 0,
      height: height ? Number(height) : 0,
      registration_date: now,
      last_visit_date: now,
      insert_by_id: req.user ? req.user.id : 1,
      flag: 1
    };

    const data = await safeInsertWithId('patients_master', newPatient);
    res.status(201).json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ROUTE 5: Load Full Patient Consultation Profile & History (Protected)
// ============================================================================
app.get('/api/patients/:id/consultation', requireAuth(['DOCTOR']), async (req, res) => {
  try {
    const patientId = Number(req.params.id);

    const { data: patient, error: patErr } = await supabase
      .from('patients_master')
      .select('*')
      .eq('id', patientId)
      .single();

    if (patErr) throw patErr;

    const { data: tickets, error: tickErr } = await supabase
      .from('ticket_master')
      .select('id, number, channeling_date, insert_date, flag')
      .eq('patient_id', patientId)
      .order('id', { ascending: false });

    if (tickErr) throw tickErr;

    const ticketIds = (tickets || []).map(t => t.id);
    const ticketDateMap = {};
    (tickets || []).forEach(t => {
      ticketDateMap[t.id] = t.channeling_date || t.insert_date;
    });

    let allergiesAndReports = '';
    let latestFindingRowId = null;
    let prescriptionHistory = [];

    if (ticketIds.length > 0) {
      const { data: findingsData } = await supabase
        .from('channeling_findings_master')
        .select('id, ticket_id, findings_comment, insert_date')
        .in('ticket_id', ticketIds)
        .order('id', { ascending: false });

      if (findingsData && findingsData.length > 0) {
        const latestWithComment = findingsData.find(f => f.findings_comment && f.findings_comment.trim() !== '') || findingsData[0];
        allergiesAndReports = latestWithComment.findings_comment || '';
        latestFindingRowId = latestWithComment.id;
      }

      const { data: channelingData } = await supabase
        .from('channeling_master')
        .select('id, ticket_id, general, reason_remarks, insert_date')
        .in('ticket_id', ticketIds)
        .order('id', { ascending: false });

      prescriptionHistory = (channelingData || [])
        .filter(c => c.general && c.general.trim() !== '')
        .map(c => ({
          id: c.id,
          ticket_id: c.ticket_id,
          general: c.general,
          reason_remarks: c.reason_remarks || '',
          visit_date: c.insert_date || ticketDateMap[c.ticket_id] || null
        }));
    }

    res.json({
      patient,
      allergiesAndReports,
      latestFindingRowId,
      prescriptionHistory
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ROUTE 6: Update "Common Details" in patients_master (Protected)
// ============================================================================
app.put('/api/patients/:id/common', requireAuth(['DOCTOR']), async (req, res) => {
  try {
    const patientId = Number(req.params.id);
    const { common } = req.body;

    const { data, error } = await supabase
      .from('patients_master')
      .update({ common: common || '' })
      .eq('id', patientId)
      .select()
      .single();

    if (error) throw error;
    res.json({ success: true, common: data.common });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ROUTE 7: Update "Allergies & Reports" (Protected + P2 Concurrency Safe)
// ============================================================================
app.put('/api/patients/:id/allergies-reports', requireAuth(['DOCTOR']), async (req, res) => {
  try {
    const patientId = Number(req.params.id);
    const { findings_comment, active_ticket_id, doctor_id } = req.body;

    let ticketId = active_ticket_id;

    if (!ticketId) {
      const { data: existingTickets } = await supabase
        .from('ticket_master')
        .select('id')
        .eq('patient_id', patientId)
        .order('id', { ascending: false })
        .limit(1);

      if (existingTickets && existingTickets.length > 0) {
        ticketId = existingTickets[0].id;
      } else {
        const today = new Date().toISOString().split('T')[0];
        const newTicket = await safeInsertWithId('ticket_master', {
          number: 1,
          booking_method: 'Direct Walk-In',
          timeframe_id: 1,
          patient_id: patientId,
          channeling_date: today,
          channeling_doctor_id: doctor_id || 1,
          institutional_fee: 0,
          billing_amount: 0,
          insert_by_id: doctor_id || 1,
          insert_date: new Date().toISOString(),
          flag: 1
        });
        ticketId = newTicket.id;
      }
    }

    const { data: existingFinding } = await supabase
      .from('channeling_findings_master')
      .select('id')
      .eq('ticket_id', ticketId)
      .order('id', { ascending: false })
      .limit(1);

    if (existingFinding && existingFinding.length > 0) {
      const { error: updErr } = await supabase
        .from('channeling_findings_master')
        .update({ findings_comment: findings_comment || '' })
        .eq('id', existingFinding[0].id);

      if (updErr) throw updErr;
    } else {
      await safeInsertWithId('channeling_findings_master', {
        ticket_id: ticketId,
        finding_id: 1,
        findings_comment: findings_comment || '',
        insert_by_id: doctor_id || 1,
        insert_date: new Date().toISOString(),
        flag: 1
      });
    }

    res.json({ success: true, ticket_id: ticketId, findings_comment });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ROUTE 8: Submit Prescription ("To Counter") (Protected + P2 Concurrency Safe)
// ============================================================================
app.post('/api/doctor/prescribe', requireAuth(['DOCTOR']), async (req, res) => {
  try {
    const { patient_id, ticket_id, general, reason_remarks, doctor_id, doctor_name, patient_name } = req.body;

    if (!patient_id || !general || !general.trim()) {
      return res.status(400).json({ error: 'Patient and prescription text are required.' });
    }

    const now = new Date();
    const slDateStr = new Intl.DateTimeFormat('en-CA', {
      timeZone: 'Asia/Colombo',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit'
    }).format(now);

    const slTimeStr = new Intl.DateTimeFormat('en-GB', {
      timeZone: 'Asia/Colombo',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false
    }).format(now);

    const slTimestamp = `${slDateStr}T${slTimeStr}+05:30`;
    let finalTicketId = ticket_id ? Number(ticket_id) : null;

    if (!finalTicketId) {
      const newTicket = await safeInsertWithId('ticket_master', {
        number: 1,
        booking_method: 'Direct Consult',
        timeframe_id: 1,
        patient_id: Number(patient_id),
        channeling_date: slDateStr,
        channeling_doctor_id: doctor_id || 1,
        institutional_fee: 0,
        billing_amount: 0,
        insert_by_id: doctor_id || 1,
        insert_date: slTimestamp,
        flag: 2
      });
      finalTicketId = newTicket.id;
    } else {
      const { error: updTickErr } = await supabase
        .from('ticket_master')
        .update({ flag: 2, channeling_doctor_id: doctor_id || 1 })
        .eq('id', finalTicketId);

      if (updTickErr) throw updTickErr;
    }

    const { data: existingChanneling } = await supabase
      .from('channeling_master')
      .select('id')
      .eq('ticket_id', finalTicketId)
      .limit(1);

    let channelingRow;

    if (existingChanneling && existingChanneling.length > 0) {
      const { data, error } = await supabase
        .from('channeling_master')
        .update({
          general: general.trim(),
          reason_remarks: reason_remarks || '',
          insert_date: slTimestamp,
          flag: 1
        })
        .eq('id', existingChanneling[0].id)
        .select()
        .single();

      if (error) throw error;
      channelingRow = data;
    } else {
      channelingRow = await safeInsertWithId('channeling_master', {
        ticket_id: finalTicketId,
        reason_remarks: reason_remarks || '',
        general: general.trim(),
        insert_by_id: doctor_id || 1,
        insert_date: slTimestamp,
        flag: 1
      });
    }

    await supabase
      .from('patients_master')
      .update({ last_visit_date: slTimestamp })
      .eq('id', Number(patient_id));

    await supabase.from('counter_alerts').insert([{
      alert_type: 'NEW_PRESCRIPTION',
      doctor_id: doctor_id || 1,
      doctor_name: doctor_name || 'Doctor',
      ticket_id: finalTicketId,
      patient_name: patient_name || 'Patient',
      message: general.trim()
    }]);

    res.json({ success: true, ticket_id: finalTicketId, channeling: channelingRow });
  } catch (err) {
    console.error('Prescribe Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ROUTE 9: Ring Counter Bell (Protected)
// ============================================================================
app.post('/api/doctor/bell', requireAuth(['DOCTOR']), async (req, res) => {
  try {
    const { doctor_id, doctor_name } = req.body;
    const { data, error } = await supabase
      .from('counter_alerts')
      .insert([{
        alert_type: 'BELL_RING',
        doctor_id: doctor_id || 1,
        doctor_name: doctor_name || 'Doctor',
        message: 'Doctor rang the counter bell!'
      }])
      .select()
      .single();

    if (error) throw error;
    res.json({ success: true, alert: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ROUTE 10: Update Marital Status in patients_master (Protected)
// ============================================================================
app.put('/api/patients/:id/marital-status', requireAuth(['DOCTOR', 'COUNTER']), async (req, res) => {
  try {
    const patientId = Number(req.params.id);
    const { married } = req.body;

    const { data, error } = await supabase
      .from('patients_master')
      .update({ married: Number(married) })
      .eq('id', patientId)
      .select()
      .single();

    if (error) throw error;
    res.json({ success: true, married: data.married });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ROUTE 11: Update Gender in patients_master (Protected)
// ============================================================================
app.put('/api/patients/:id/gender', requireAuth(['DOCTOR', 'COUNTER']), async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('patients_master')
      .update({ gender: Number(req.body.gender) })
      .eq('id', Number(req.params.id))
      .select().single();
    if (error) throw error;
    res.json({ success: true, gender: data.gender });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ROUTE 12: Update Phone Number in patients_master (Protected)
// ============================================================================
app.put('/api/patients/:id/phone', requireAuth(['DOCTOR', 'COUNTER']), async (req, res) => {
  try {
    const patientId = Number(req.params.id);
    const rawPhone = (req.body.phone || '').trim();

    const { data, error } = await supabase
      .from('patients_master')
      .update({ phone: rawPhone })
      .eq('id', patientId)
      .select()
      .single();

    if (error) throw error;
    res.json({ success: true, phone: data.phone });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ROUTE 12B: Update Demographic Details in patients_master (Protected - Counter & Doctor)
// ============================================================================
app.put('/api/patients/:id/demographics', requireAuth(['DOCTOR', 'COUNTER']), async (req, res) => {
  try {
    const patientId = Number(req.params.id);
    const { name, birth_date, phone, id_number, gender, married } = req.body;

    if (name !== undefined && !name.trim()) {
      return res.status(400).json({ error: 'Patient full name cannot be empty.' });
    }

    const updates = {};
    if (name !== undefined) updates.name = name.trim();
    if (birth_date !== undefined) {
      const cleanBirthDate = birth_date ? String(birth_date).trim() : null;
      if (cleanBirthDate && !isValidIsoDate(cleanBirthDate)) {
        return res.status(400).json({ error: 'Invalid Date of Birth format. Please use YYYY-MM-DD.' });
      }
      updates.birth_date = cleanBirthDate;
    }
    if (phone !== undefined) updates.phone = (phone || '').trim();
    if (id_number !== undefined) updates.id_number = (id_number || '').trim();
    if (gender !== undefined && gender !== '') updates.gender = Number(gender);
    if (married !== undefined && married !== '') updates.married = Number(married);

    const { data, error } = await supabase
      .from('patients_master')
      .update(updates)
      .eq('id', patientId)
      .select('id, name, birth_date, phone, id_number, gender, married, weight, height')
      .single();

    if (error) throw error;
    res.json({ success: true, patient: data });
  } catch (err) {
    console.error('Update Demographics Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ROUTE 13: Get Investigation Catalog (Protected)
// ============================================================================
const DEFAULT_INVESTIGATION_CATALOG = [
  { id: 1, investigation: 'FBC', remarks: 'Full Blood Count' },
  { id: 2, investigation: 'FBS', remarks: 'Fasting Blood Sugar' },
  { id: 3, investigation: 'HBA1C', remarks: 'Hemoglobin A1C' },
  { id: 4, investigation: 'ESR', remarks: 'Erythrocyte Sedimentation Rate' },
  { id: 5, investigation: 'CRP', remarks: 'C-Reactive Protein' },
  { id: 6, investigation: 'BUN', remarks: 'Blood Urea Nitrogen' },
  { id: 7, investigation: 'SCR', remarks: 'Serum Creatinine' },
  { id: 8, investigation: 'UFR', remarks: 'Uroflowmetry' },
  { id: 9, investigation: 'TSH', remarks: 'Thyroid Stimulating Hormone' },
  { id: 10, investigation: 'Thyroxine', remarks: 'Thyroxine (Free T4 / Total T4)' },
  { id: 11, investigation: 'SGPT', remarks: 'Serum Glutamic Pyruvic Transaminase' },
  { id: 12, investigation: 'Lipid Profile', remarks: 'Lipid Profile' },
  { id: 13, investigation: 'Others', remarks: 'Others' }
];

app.get('/api/doctor/investigation-catalog', requireAuth(['DOCTOR', 'ADMIN', 'COUNTER']), async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('investigation_master')
      .select('id, investigation, remarks')
      .order('id', { ascending: true });

    if (error || !data || data.length === 0) {
      return res.json(DEFAULT_INVESTIGATION_CATALOG);
    }
    res.json(data);
  } catch {
    res.json(DEFAULT_INVESTIGATION_CATALOG);
  }
});

// ============================================================================
// ROUTE 14: Get Patient Vitals & BMI History (Protected)
// ============================================================================
app.get('/api/doctor/patients/:id/vitals', requireAuth(['DOCTOR', 'ADMIN', 'COUNTER']), async (req, res) => {
  try {
    const patientId = Number(req.params.id);
    const { data, error } = await supabase
      .from('patient_vitals')
      .select('*')
      .eq('patient_id', patientId)
      .order('record_date', { ascending: false })
      .order('id', { ascending: false });

    if (error) {
      // Table might not exist yet
      console.warn('[Vitals GET] Warning:', error.message);
      return res.json([]);
    }
    res.json(data || []);
  } catch (err) {
    res.json([]);
  }
});

// ============================================================================
// ROUTE 15: Record New Patient Vitals (Protected)
// ============================================================================
app.post('/api/doctor/patients/:id/vitals', requireAuth(['DOCTOR', 'ADMIN', 'COUNTER']), async (req, res) => {
  try {
    const patientId = Number(req.params.id);
    const {
      record_date,
      weight_kg,
      height_cm,
      systolic_bp,
      diastolic_bp,
      pulse_bpm,
      notes
    } = req.body;

    const w = weight_kg ? parseFloat(weight_kg) : null;
    const h = height_cm ? parseFloat(height_cm) : null;
    let computedBmi = null;
    if (w && h && h > 0) {
      const hMeters = h / 100;
      computedBmi = Number((w / (hMeters * hMeters)).toFixed(2));
    }

    const payload = {
      patient_id: patientId,
      record_date: record_date || new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Colombo' }).format(new Date()),
      weight_kg: w,
      height_cm: h,
      bmi: computedBmi,
      systolic_bp: systolic_bp ? parseInt(systolic_bp, 10) : null,
      diastolic_bp: diastolic_bp ? parseInt(diastolic_bp, 10) : null,
      pulse_bpm: pulse_bpm ? parseInt(pulse_bpm, 10) : null,
      notes: notes ? String(notes).trim() : null
    };

    let record = null;
    try {
      const { data, error } = await supabase
        .from('patient_vitals')
        .insert([payload])
        .select()
        .single();
      if (error) throw error;
      record = data;
    } catch {
      // fallback with safeInsertWithId
      record = await safeInsertWithId('patient_vitals', payload);
    }

    // Optional: update baseline weight/height in patients_master too
    if (w || h) {
      try {
        const updates = {};
        if (w) updates.weight = String(w);
        if (h) updates.height = String(h);
        await supabase.from('patients_master').update(updates).eq('id', patientId);
      } catch {
        // non-blocking
      }
    }

    res.json({ success: true, record });
  } catch (err) {
    console.error('Error recording vitals:', err);
    res.status(500).json({ error: err.message || 'Failed to save vitals.' });
  }
});

// ============================================================================
// ROUTE 16: Update Existing Vitals Record (Fix Errors) (Protected)
// ============================================================================
app.put('/api/doctor/vitals/:vitalId', requireAuth(['DOCTOR', 'ADMIN']), async (req, res) => {
  try {
    const vitalId = Number(req.params.vitalId);
    const {
      record_date,
      weight_kg,
      height_cm,
      systolic_bp,
      diastolic_bp,
      pulse_bpm,
      notes
    } = req.body;

    const w = weight_kg ? parseFloat(weight_kg) : null;
    const h = height_cm ? parseFloat(height_cm) : null;
    let computedBmi = null;
    if (w && h && h > 0) {
      const hMeters = h / 100;
      computedBmi = Number((w / (hMeters * hMeters)).toFixed(2));
    }

    const updates = {
      record_date,
      weight_kg: w,
      height_cm: h,
      bmi: computedBmi,
      systolic_bp: systolic_bp ? parseInt(systolic_bp, 10) : null,
      diastolic_bp: diastolic_bp ? parseInt(diastolic_bp, 10) : null,
      pulse_bpm: pulse_bpm ? parseInt(pulse_bpm, 10) : null,
      notes: notes ? String(notes).trim() : null
    };

    const { data, error } = await supabase
      .from('patient_vitals')
      .update(updates)
      .eq('id', vitalId)
      .select()
      .single();

    if (error) throw error;
    res.json({ success: true, record: data });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to update vitals record.' });
  }
});

// ============================================================================
// ROUTE 17: Delete Vitals Record (Protected)
// ============================================================================
app.delete('/api/doctor/vitals/:vitalId', requireAuth(['DOCTOR', 'ADMIN']), async (req, res) => {
  try {
    const vitalId = Number(req.params.vitalId);
    const { error } = await supabase
      .from('patient_vitals')
      .delete()
      .eq('id', vitalId);

    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to delete vitals record.' });
  }
});

// ============================================================================
// ROUTE 18: Get Patient Lab Investigations History (Protected)
// ============================================================================
app.get('/api/doctor/patients/:id/investigations', requireAuth(['DOCTOR', 'ADMIN', 'COUNTER']), async (req, res) => {
  try {
    const patientId = Number(req.params.id);
    const { data, error } = await supabase
      .from('patient_investigations')
      .select('*')
      .eq('patient_id', patientId)
      .order('test_date', { ascending: false })
      .order('id', { ascending: false });

    if (error) {
      console.warn('[Investigations GET] Warning:', error.message);
      return res.json([]);
    }
    res.json(data || []);
  } catch {
    res.json([]);
  }
});

// ============================================================================
// ROUTE 19: Record New Lab Investigation (Protected)
// ============================================================================
app.post('/api/doctor/patients/:id/investigations', requireAuth(['DOCTOR', 'ADMIN', 'COUNTER']), async (req, res) => {
  try {
    const patientId = Number(req.params.id);
    const {
      investigation_id,
      test_name,
      test_date,
      results,
      remarks
    } = req.body;

    const payload = {
      patient_id: patientId,
      investigation_id: investigation_id ? Number(investigation_id) : null,
      test_name: String(test_name || 'Lab Test').trim(),
      test_date: test_date || new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Colombo' }).format(new Date()),
      results: typeof results === 'object' && results !== null ? results : {},
      remarks: remarks ? String(remarks).trim() : null
    };

    let record = null;
    try {
      const { data, error } = await supabase
        .from('patient_investigations')
        .insert([payload])
        .select()
        .single();
      if (error) throw error;
      record = data;
    } catch {
      record = await safeInsertWithId('patient_investigations', payload);
    }

    res.json({ success: true, record });
  } catch (err) {
    console.error('Error saving lab investigation:', err);
    res.status(500).json({ error: err.message || 'Failed to save lab investigation.' });
  }
});

// ============================================================================
// ROUTE 20: Update Existing Lab Investigation (Fix Errors) (Protected)
// ============================================================================
app.put('/api/doctor/investigations/:invId', requireAuth(['DOCTOR', 'ADMIN']), async (req, res) => {
  try {
    const invId = Number(req.params.invId);
    const {
      investigation_id,
      test_name,
      test_date,
      results,
      remarks
    } = req.body;

    const updates = {
      investigation_id: investigation_id ? Number(investigation_id) : null,
      test_name: String(test_name).trim(),
      test_date,
      results: typeof results === 'object' && results !== null ? results : {},
      remarks: remarks ? String(remarks).trim() : null
    };

    const { data, error } = await supabase
      .from('patient_investigations')
      .update(updates)
      .eq('id', invId)
      .select()
      .single();

    if (error) throw error;
    res.json({ success: true, record: data });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to update lab investigation.' });
  }
});

// ============================================================================
// ROUTE 21: Delete Lab Investigation Record (Protected)
// ============================================================================
app.delete('/api/doctor/investigations/:invId', requireAuth(['DOCTOR', 'ADMIN']), async (req, res) => {
  try {
    const invId = Number(req.params.invId);
    const { error } = await supabase
      .from('patient_investigations')
      .delete()
      .eq('id', invId);

    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to delete lab investigation.' });
  }
});

// ============================================================================
// ROUTE 22: Doctor's Daily Clinical Log (Protected - Doctor & Admin)
// ============================================================================
app.get('/api/doctor/daily-log', requireAuth(['DOCTOR', 'ADMIN']), async (req, res) => {
  try {
    const targetDate = (req.query.date || '').trim() || new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Colombo' }).format(new Date());
    const startIso = `${targetDate}T00:00:00.000+05:30`;
    const endIso = `${targetDate}T23:59:59.999+05:30`;

    // 1. Fetch tickets for the selected day
    const { data: ticketsData, error: tickErr } = await supabase
      .from('ticket_master')
      .select('id, number, patient_id, channeling_date, insert_date, flag, channeling_doctor_id')
      .eq('channeling_date', targetDate)
      .order('id', { ascending: true });

    if (tickErr) throw tickErr;
    let tickets = ticketsData || [];

    // 2. Fetch channeling (prescription) records for these tickets
    const ticketIds = tickets.map(t => t.id);
    let channelings = [];
    if (ticketIds.length > 0) {
      const { data: chanData, error: chanErr } = await supabase
        .from('channeling_master')
        .select('id, ticket_id, general, reason_remarks, insert_date, insert_by_id')
        .in('ticket_id', ticketIds)
        .order('id', { ascending: true });
      if (!chanErr && chanData) channelings = chanData;
    }

    // Also check any channeling records inserted on this date
    const { data: dateChannelings } = await supabase
      .from('channeling_master')
      .select('id, ticket_id, general, reason_remarks, insert_date, insert_by_id')
      .gte('insert_date', startIso)
      .lte('insert_date', endIso);

    const allChannelingsMap = {};
    (channelings || []).forEach(c => { allChannelingsMap[c.ticket_id] = c; });
    const additionalTicketIds = [];
    (dateChannelings || []).forEach(c => {
      if (!allChannelingsMap[c.ticket_id]) {
        allChannelingsMap[c.ticket_id] = c;
        if (!ticketIds.includes(c.ticket_id)) additionalTicketIds.push(c.ticket_id);
      }
    });

    if (additionalTicketIds.length > 0) {
      const { data: extraTickets } = await supabase
        .from('ticket_master')
        .select('id, number, patient_id, channeling_date, insert_date, flag, channeling_doctor_id')
        .in('id', additionalTicketIds);
      if (extraTickets) tickets = [...tickets, ...extraTickets];
    }

    // 3. Fetch patient profiles
    const patientIds = [...new Set(tickets.map(t => t.patient_id).filter(Boolean))];
    let patients = [];
    if (patientIds.length > 0) {
      const { data: patData } = await supabase
        .from('patients_master')
        .select('id, name, phone, gender, birth_date, id_number')
        .in('id', patientIds);
      if (patData) patients = patData;
    }
    const patMap = {};
    patients.forEach(p => { patMap[p.id] = p; });

    // 4. Fetch pharmacy bills for today's revenue & status
    const { data: billsData } = await supabase
      .from('pharmacy_bills')
      .select('*')
      .gte('created_at', startIso)
      .lte('created_at', endIso)
      .order('id', { ascending: true });
    const bills = billsData || [];

    const ticketToBillMap = {};
    const matchedBillIds = new Set();
    bills.forEach(b => {
      if (Array.isArray(b.ticket_ids)) {
        b.ticket_ids.forEach(tId => {
          ticketToBillMap[tId] = b;
        });
      }
    });

    // 5. Build consolidated rows
    const rows = [];
    const processedTickets = new Set();

    tickets.forEach(t => {
      if (processedTickets.has(t.id)) return;
      processedTickets.add(t.id);

      const chan = allChannelingsMap[t.id] || {};
      const pat = patMap[t.patient_id] || {};
      const bill = ticketToBillMap[t.id] || null;
      if (bill) matchedBillIds.add(bill.id);

      const isOutdoor = bill?.bill_status === 'OUTDOOR_RX';
      const rev = bill ? (isOutdoor ? 0 : Number(bill.final_total || 0)) : 0;

      let status = 'WAITING';
      if (bill) {
        status = isOutdoor ? 'OUTDOOR_RX' : 'COMPLETED_BILL';
      } else if (t.flag === 2) {
        status = 'AT_COUNTER';
      } else if (chan.general) {
        status = 'PRESCRIBED';
      }

      rows.push({
        id: `ticket-${t.id}`,
        ticket_id: t.id,
        ticket_number: t.number || t.id,
        time: chan.insert_date || t.insert_date || startIso,
        patient_id: pat.id || t.patient_id,
        patient_name: pat.name || bill?.patient_names || 'Patient',
        patient_phone: pat.phone || bill?.patient_phone || '',
        gender: pat.gender !== undefined && pat.gender !== null ? Number(pat.gender) : null,
        birth_date: pat.birth_date || null,
        id_number: pat.id_number || '',
        prescription: chan.general || '',
        remarks: chan.reason_remarks || '',
        bill_id: bill?.id || null,
        daily_bill_no: bill?.daily_bill_no || null,
        bill_status: status,
        revenue: rev,
        auth_code: bill?.auth_code || ''
      });
    });

    // Also include any standalone bills created on that day
    bills.forEach(b => {
      if (!matchedBillIds.has(b.id)) {
        const isOutdoor = b.bill_status === 'OUTDOOR_RX';
        const rev = isOutdoor ? 0 : Number(b.final_total || 0);
        const medRx = (b.items_snapshot || [])
          .filter(i => i.item_type === 'MEDICINE')
          .map(i => `${i.item_name} × ${i.quantity}`)
          .join(', ');

        rows.push({
          id: `bill-${b.id}`,
          ticket_id: Array.isArray(b.ticket_ids) && b.ticket_ids.length > 0 ? b.ticket_ids[0] : null,
          ticket_number: b.daily_bill_no || b.id,
          time: b.created_at,
          patient_id: null,
          patient_name: b.patient_names || 'Walk-In Patient',
          patient_phone: b.patient_phone || '',
          gender: null,
          birth_date: null,
          id_number: '',
          prescription: medRx || 'Direct Counter Dispense',
          remarks: '',
          bill_id: b.id,
          daily_bill_no: b.daily_bill_no || b.id,
          bill_status: b.bill_status,
          revenue: rev,
          auth_code: b.auth_code || ''
        });
      }
    });

    // Chronological ordering
    rows.sort((a, b) => new Date(a.time) - new Date(b.time));

    rows.forEach((r, idx) => {
      r.index = idx + 1;
    });

    const totalRevenue = bills
      .filter(b => b.bill_status !== 'OUTDOOR_RX')
      .reduce((sum, b) => sum + Number(b.final_total || 0), 0);

    const totalPatients = rows.length;
    const paidBillsCount = bills.filter(b => b.bill_status === 'COMPLETED_BILL').length;
    const outdoorCount = bills.filter(b => b.bill_status === 'OUTDOOR_RX').length;

    res.json({
      success: true,
      date: targetDate,
      summary: {
        totalPatients,
        totalRevenue,
        paidBillsCount,
        outdoorCount
      },
      records: rows
    });
  } catch (err) {
    console.error('Doctor Daily Log Error:', err.message);
    res.status(500).json({ error: err.message || 'Failed to load doctor daily log.' });
  }
});

// ============================================================================
// COUNTER ROUTE 1: Encrypted Counter Staff Login (Rate-Limited + Issues JWT)
// ============================================================================
app.post('/api/counter/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }

    const { data: staff, error } = await supabase
      .from('counter_staff_master')
      .select('id, name, role, username, password, flag')
      .eq('username', username.trim())
      .eq('flag', 1)
      .single();

    if (error || !staff) {
      return res.status(401).json({ error: 'Invalid counter username or password.' });
    }

    const isMatch = await bcrypt.compare(password, staff.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid counter username or password.' });
    }

    await supabase
      .from('counter_staff_master')
      .update({ is_online: true })
      .eq('id', staff.id);

    const token = signJWT({
      id: staff.id,
      name: staff.name,
      username: staff.username,
      role: 'COUNTER'
    });

    res.json({
      id: staff.id,
      name: staff.name,
      role: staff.role,
      username: staff.username,
      token
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// COUNTER ROUTE 2: Fetch Active Prescriptions Sent to Counter (Protected)
// ============================================================================
app.get('/api/counter/prescriptions', requireAuth(['COUNTER', 'DOCTOR']), async (req, res) => {
  try {
    const { data: tickets, error: tickErr } = await supabase
      .from('ticket_master')
      .select('*')
      .eq('flag', 2)
      .order('id', { ascending: true })
      .limit(50);

    if (tickErr) throw tickErr;
    if (!tickets || tickets.length === 0) return res.json([]);

    const patientIds = [...new Set(tickets.map(t => t.patient_id).filter(Boolean))];
    const ticketIds = tickets.map(t => t.id);

    const [{ data: patients }, { data: channelings }, { data: doctors }] = await Promise.all([
      supabase.from('patients_master').select('id, name, phone, birth_date, gender').in('id', patientIds),
      supabase.from('channeling_master').select('ticket_id, general, reason_remarks, insert_date').in('ticket_id', ticketIds).order('id', { ascending: false }),
      supabase.from('doctors_master').select('id, name')
    ]);

    const patMap = {};
    (patients || []).forEach(p => { patMap[p.id] = p; });

    const rxMap = {};
    (channelings || []).forEach(c => {
      if (!rxMap[c.ticket_id]) rxMap[c.ticket_id] = c;
    });

    const docMap = {};
    (doctors || []).forEach(d => { docMap[d.id] = d.name; });

    const list = tickets
      .map(t => ({
        ticket_id: t.id,
        ticket_number: t.number || t.id,
        doctor_name: docMap[t.channeling_doctor_id] || 'Consulting Physician',
        patient: patMap[t.patient_id] || null,
        prescription: rxMap[t.id]?.general || 'Consultation Completed (No shorthand text)',
        sent_at: rxMap[t.id]?.insert_date || t.insert_date
      }))
      .filter(item => item.patient !== null);

    res.json(list);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// COUNTER ROUTE 3: Load Medicines & Dispensary Services Catalog (Protected)
// ============================================================================
app.get('/api/counter/catalog', requireAuth(['COUNTER', 'DOCTOR', 'GRN']), async (req, res) => {
  try {
    const [{ data: medicines, error: medErr }, { data: services, error: srvErr }] = await Promise.all([
      supabase.from('medicines_master').select('*').eq('flag', 1).order('name', { ascending: true }),
      supabase.from('clinic_services_master').select('*').eq('flag', 1).order('id', { ascending: true })
    ]);

    if (medErr) throw medErr;
    if (srvErr) throw srvErr;

    res.json({
      medicines: medicines || [],
      services: services || []
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// COUNTER ROUTE 4: Save or Auto-Update Medicine Price in Database (Protected)
// ============================================================================
app.post('/api/counter/medicines/upsert', requireAuth(['COUNTER', 'ADMIN', 'GRN', 'DOCTOR']), async (req, res) => {
  try {
    const { id, name, unit_price } = req.body;
    const cleanName = (name || '').trim();
    const cleanPrice = Number(unit_price) || 0;

    if (!cleanName) {
      return res.status(400).json({ error: 'Medicine name is required' });
    }

    if (id) {
      const { data, error } = await supabase
        .from('medicines_master')
        .update({ unit_price: cleanPrice, updated_at: new Date().toISOString() })
        .eq('id', id)
        .select()
        .single();
      if (error) throw error;
      return res.json(data);
    } else {
      const { data, error } = await supabase
        .from('medicines_master')
        .upsert([{ name: cleanName, unit_price: cleanPrice, updated_at: new Date().toISOString(), flag: 1 }], { onConflict: 'name' })
        .select()
        .single();
      if (error) throw error;
      return res.json(data);
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// COUNTER ROUTE 5: Check & Clear Doctor Bell Alerts (Protected)
// ============================================================================
app.get('/api/counter/alerts', requireAuth(['COUNTER', 'DOCTOR']), async (req, res) => {
  try {
    // Only return bell rings from the last 24 hours to prevent yesterday's bell from sounding today
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

    const { data, error } = await supabase
      .from('counter_alerts')
      .select('*')
      .eq('alert_type', 'BELL_RING')
      .gte('created_at', twentyFourHoursAgo)
      .order('id', { ascending: false })
      .limit(1);

    if (error) {
      // Fallback without timestamp filter if created_at column isn't present
      const fallback = await supabase
        .from('counter_alerts')
        .select('*')
        .eq('alert_type', 'BELL_RING')
        .order('id', { ascending: false })
        .limit(1);
      return res.json(fallback.data && fallback.data.length > 0 ? fallback.data[0] : null);
    }

    res.json(data && data.length > 0 ? data[0] : null);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// COUNTER ROUTE 6: Complete POS Checkout OR Outdoor Medicine Removal (Protected)
// ============================================================================
app.post('/api/counter/checkout', requireAuth(['COUNTER', 'DOCTOR', 'ADMIN']), async (req, res) => {
  try {
    const {
      ticket_ids,
      patient_names,
      patient_phone,
      doctor_name,
      bill_status,
      calculated_total,
      final_total,
      items_snapshot,
      created_by
    } = req.body;

    if (Array.isArray(ticket_ids) && ticket_ids.length > 0) {
      const { error: tickErr } = await supabase
        .from('ticket_master')
        .update({ flag: 3, billing_amount: Number(final_total) || 0 })
        .in('id', ticket_ids);
      if (tickErr) throw tickErr;
    }

    const { startISO, endISO } = getSriLankaTodayRange();
    const { count: todayCount } = await supabase
      .from('pharmacy_bills')
      .select('id', { count: 'exact', head: true })
      .gte('created_at', startISO)
      .lte('created_at', endISO);

    const dailyBillNumber = (todayCount || 0) + 1;

    const totalMedicineCost = (items_snapshot || [])
      .filter(item => item.item_type === 'MEDICINE')
      .reduce((sum, item) => sum + (Number(item.line_total) || 0), 0);

    const authCode = generateAuthCode();

    const billPayload = {
      ticket_ids: ticket_ids || [],
      patient_names: patient_names || 'Walk-In Patient',
      patient_phone: patient_phone || '',
      doctor_name: doctor_name || 'Consulting Physician',
      bill_status: bill_status || 'COMPLETED_BILL',
      calculated_total: Number(calculated_total) || 0,
      final_total: Number(final_total) || 0,
      total_medicine_cost: totalMedicineCost,
      items_snapshot: items_snapshot || [],
      created_by: created_by || (req.user ? req.user.name : 'Counter'),
      auth_code: authCode
    };

    let bill;
    try {
      // First attempt safeInsertWithId for tables without sequence or with collision retry
      bill = await safeInsertWithId('pharmacy_bills', billPayload);
    } catch (insertWithIdErr) {
      console.warn('[Checkout] safeInsertWithId failed, checking for column compatibility:', insertWithIdErr.message);
      const isColumnMissing = String(insertWithIdErr.message || '').includes('auth_code');
      const payloadToUse = isColumnMissing
        ? {
            ...billPayload,
            items_snapshot: [...(billPayload.items_snapshot || []), { _auth_code: authCode }]
          }
        : billPayload;
      if (isColumnMissing) delete payloadToUse.auth_code;

      try {
        bill = await safeInsertWithId('pharmacy_bills', payloadToUse);
      } catch {
        const { data: stdBill, error: billErr } = await supabase
          .from('pharmacy_bills')
          .insert([payloadToUse])
          .select()
          .single();
        if (billErr) throw billErr;
        bill = stdBill;
      }
    }

    res.json({
      success: true,
      bill: {
        ...bill,
        daily_bill_no: dailyBillNumber,
        auth_code: bill.auth_code || authCode
      }
    });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// COUNTER ROUTE 7: Get Today's Log with Daily Bill Numbers (Protected)
// ============================================================================
app.get('/api/counter/today-log', requireAuth(['COUNTER', 'ADMIN', 'DOCTOR']), async (req, res) => {
  try {
    const { startISO, endISO } = getSriLankaTodayRange();

    const { data, error } = await supabase
      .from('pharmacy_bills')
      .select('*')
      .gte('created_at', startISO)
      .lte('created_at', endISO)
      .order('id', { ascending: true });

    if (error) throw error;

    const numberedList = (data || [])
      .map((row, index) => ({
        ...row,
        daily_bill_no: index + 1
      }))
      .reverse();

    res.json(numberedList);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// COUNTER ROUTE 8: Add Patient to Today's Active Doctor Queue (Protected + P2)
// ============================================================================
app.post('/api/counter/queue/add', requireAuth(['COUNTER', 'DOCTOR']), async (req, res) => {
  try {
    const { patient_id, doctor_id } = req.body;
    if (!patient_id) {
      return res.status(400).json({ error: 'Patient ID is required.' });
    }

    const { dateStr: todaySL } = getSriLankaTodayRange();

    const { data: existingWaiting } = await supabase
      .from('ticket_master')
      .select('id, number')
      .eq('patient_id', Number(patient_id))
      .eq('channeling_date', todaySL)
      .eq('flag', 1)
      .limit(1);

    if (existingWaiting && existingWaiting.length > 0) {
      return res.status(400).json({ error: 'This patient is already in today\'s active waiting queue.' });
    }

    const { count: todayTicketsCount } = await supabase
      .from('ticket_master')
      .select('id', { count: 'exact', head: true })
      .eq('channeling_date', todaySL);

    const nextDailyNumber = (todayTicketsCount || 0) + 1;

    const newTicket = await safeInsertWithId('ticket_master', {
      number: nextDailyNumber,
      booking_method: 'Counter Queue',
      timeframe_id: 1,
      patient_id: Number(patient_id),
      channeling_date: todaySL,
      channeling_doctor_id: doctor_id || 1,
      institutional_fee: 0,
      billing_amount: 0,
      insert_by_id: req.user ? req.user.id : 1,
      insert_date: new Date().toISOString(),
      flag: 1
    });

    res.json({ success: true, ticket: newTicket, daily_number: nextDailyNumber });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// COUNTER ROUTE 9: Remove / Cancel Patient from Active Queue (Protected)
// ============================================================================
app.put('/api/counter/queue/:ticketId/cancel', requireAuth(['COUNTER', 'DOCTOR']), async (req, res) => {
  try {
    const ticketId = Number(req.params.ticketId);
    const { error } = await supabase
      .from('ticket_master')
      .update({ flag: 0 })
      .eq('id', ticketId);

    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ADMIN ROUTE 1: Encrypted Admin Login (Rate-Limited + Issues JWT)
// ============================================================================
app.post('/api/admin/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });

    const { data: admin, error } = await supabase
      .from('admin_master')
      .select('id, name, username, password')
      .eq('username', username.trim())
      .eq('flag', 1)
      .single();

    if (error || !admin) return res.status(401).json({ error: 'Invalid admin credentials.' });

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid admin credentials.' });

    const token = signJWT({
      id: admin.id,
      name: admin.name,
      username: admin.username,
      role: 'ADMIN'
    });

    res.json({
      id: admin.id,
      name: admin.name,
      username: admin.username,
      role: 'Administrator',
      token
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Aggregates ALL medicines dispensed across pharmacy_bills in [startIso, endIso], sorted most -> least
async function fetchAllDispensedMedicines(startIso, endIso) {
  const medMap = new Map();
  const batchSize = 1000;
  let offset = 0;

  while (true) {
    const { data: billsBatch, error } = await supabase
      .from('pharmacy_bills')
      .select('bill_status, items_snapshot')
      .gte('created_at', startIso)
      .lte('created_at', endIso)
      .order('id', { ascending: true })
      .range(offset, offset + batchSize - 1);

    if (error) throw error;
    if (!billsBatch || billsBatch.length === 0) break;

    for (const bill of billsBatch) {
      if (bill.bill_status === 'OUTDOOR_RX') continue;
      const items = Array.isArray(bill.items_snapshot) ? bill.items_snapshot : [];
      for (const item of items) {
        if (!item || item._auth_code) continue;
        if (item.item_type !== 'MEDICINE') continue;

        const rawName = String(item.name || '').trim();
        if (!rawName) continue;

        const qty = Number(item.qty ?? item.quantity ?? 0);
        if (!Number.isFinite(qty) || qty <= 0) continue;

        const lineTotal = Number(item.line_total || 0);
        const key = rawName.toLowerCase();
        const existing = medMap.get(key);
        if (existing) {
          existing.total_sold += qty;
          existing.total_revenue += Number.isFinite(lineTotal) ? lineTotal : 0;
          existing.bill_count += 1;
        } else {
          medMap.set(key, {
            name: rawName,
            total_sold: qty,
            total_revenue: Number.isFinite(lineTotal) ? lineTotal : 0,
            bill_count: 1
          });
        }
      }
    }

    if (billsBatch.length < batchSize) break;
    offset += batchSize;
  }

  return Array.from(medMap.values())
    .map(m => ({
      ...m,
      total_sold: Math.round(m.total_sold * 100) / 100,
      total_revenue: Math.round(m.total_revenue * 100) / 100
    }))
    .filter(m => m.total_sold > 0)
    .sort((a, b) => (b.total_sold - a.total_sold) || a.name.localeCompare(b.name));
}

// ============================================================================
// ADMIN ROUTE 2: Financial Dashboard Analytics (Protected - Admin Only)
// ============================================================================
app.get('/api/admin/finance', requireAuth(['ADMIN']), async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    
    const startIso = startDate ? `${startDate}T00:00:00.000+05:30` : '2010-01-01T00:00:00.000+05:30';
    const endIso = endDate ? `${endDate}T23:59:59.999+05:30` : '2050-12-31T23:59:59.999+05:30';

    const [
      { data: finData, error: finErr },
      { data: topMedsRpc, error: medErr },
      allDispensedMeds,
      { data: traffic, error: trafErr }
    ] = await Promise.all([
      supabase.rpc('get_financial_metrics', { start_d: startIso, end_d: endIso }),
      supabase.rpc('get_top_medicines', { start_d: startIso, end_d: endIso }),
      fetchAllDispensedMedicines(startIso, endIso),
      supabase.rpc('get_weekly_traffic', { start_d: startIso, end_d: endIso })
    ]);

    if (finErr) throw finErr;
    if (medErr) throw medErr;
    if (trafErr) throw trafErr;

    const topMedicines = allDispensedMeds.length > 0 ? allDispensedMeds : (topMedsRpc || []);

    res.json({
      summary: finData.summary,
      chartData: finData.daily,
      topMedicines,
      weeklyTraffic: traffic
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ADMIN ROUTE 3: Patient Demographics & Age Bell Curve (Protected - Admin Only)
// ============================================================================
app.get('/api/admin/demographics', requireAuth(['ADMIN']), async (req, res) => {
  try {
    const { data, error } = await supabase.rpc('get_patient_demographics');
    
    if (error) {
      console.error("SUPABASE RPC CRASH ERROR:", error);
      throw error;
    }

    const bellCurveData = Object.keys(data.age).map(range => ({
      ageGroup: range,
      patients: data.age[range]
    }));

    const genderData = [
      { name: 'Male', value: data.gender.male, fill: '#38bdf8' },
      { name: 'Female', value: data.gender.female, fill: '#f472b6' },
      { name: 'Not Specified', value: data.gender.unspecified, fill: '#64748b' }
    ];

    res.json({
      bellCurveData,
      genderData,
      totalRegistered: data.total
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ADMIN ROUTE 4: Daily Business Spreadsheet Log (Protected - Admin Only)
// ============================================================================
app.get('/api/admin/daily-log', requireAuth(['ADMIN']), async (req, res) => {
  try {
    const { date } = req.query;
    if (!date) return res.status(400).json({ error: 'Date is required' });

    const startIso = `${date}T00:00:00.000+05:30`;
    const endIso = `${date}T23:59:59.999+05:30`;

    const { data, error } = await supabase
      .from('pharmacy_bills')
      .select('*')
      .gte('created_at', startIso)
      .lte('created_at', endIso)
      .order('id', { ascending: true });

    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ADMIN ROUTE 5: Get All Registered Users (Protected - Admin Only)
// ============================================================================
app.get('/api/admin/users', requireAuth(['ADMIN']), async (req, res) => {
  try {
    const [docs, cashiers] = await Promise.all([
      supabase.from('doctors_master').select('id, name, username, specialty').eq('flag', 1),
      supabase.from('counter_staff_master').select('id, name, username, role').eq('flag', 1)
    ]);
    res.json({
      doctors: docs.data || [],
      cashiers: cashiers.data || []
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ADMIN ROUTE 6: Register New Doctor or Cashier (Protected - Admin Only)
// ============================================================================
app.post('/api/admin/users', requireAuth(['ADMIN']), async (req, res) => {
  try {
    const { role_type, name, username, password, specialty_or_role } = req.body;
    if (!name || !username || !password) return res.status(400).json({ error: 'Missing fields' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const table = role_type === 'DOCTOR' ? 'doctors_master' : 'counter_staff_master';
    
    const payload = {
      name, username, password: hashedPassword,
      ...(role_type === 'DOCTOR' ? { specialty: specialty_or_role } : { role: specialty_or_role })
    };

    const { data, error } = await supabase.from(table).insert([payload]).select().single();
    if (error) {
      if (error.code === '23505') return res.status(400).json({ error: 'Username already exists.' });
      throw error;
    }
    res.json({ success: true, user: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ADMIN ROUTE 7: Delete User (Protected - Admin Only)
// ============================================================================
app.delete('/api/admin/users/:type/:id', requireAuth(['ADMIN']), async (req, res) => {
  try {
    const table = req.params.type === 'DOCTOR' ? 'doctors_master' : 'counter_staff_master';
    const { error } = await supabase.from(table).update({ flag: 0 }).eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ADMIN ROUTE 8: Authenticate & Verify Bill by Auth Code (Protected)
// ============================================================================
app.get('/api/admin/verify-bill/:code', requireAuth(['ADMIN', 'DOCTOR', 'COUNTER']), async (req, res) => {
  try {
    let cleanCode = (req.params.code || '').trim().toUpperCase();
    if (!cleanCode) {
      return res.status(400).json({ error: 'Auth code is required.' });
    }
    // Allow searching '7X8K' without having to type 'WSP-'
    if (!cleanCode.startsWith('WSP-') && cleanCode.length === 4) {
      cleanCode = `WSP-${cleanCode}`;
    }

    let bill = null;

    // 1. Primary lookup by auth_code column
    try {
      const { data, error } = await supabase
        .from('pharmacy_bills')
        .select('*')
        .eq('auth_code', cleanCode)
        .maybeSingle();
      if (!error && data) bill = data;
    } catch {
      // Column might not exist yet
    }

    // 2. Fallback lookup in items_snapshot
    if (!bill) {
      const { data: recentBills } = await supabase
        .from('pharmacy_bills')
        .select('*')
        .order('id', { ascending: false })
        .limit(300);

      if (recentBills && recentBills.length > 0) {
        bill = recentBills.find(b => {
          if (b.auth_code && b.auth_code.toUpperCase() === cleanCode) return true;
          if (Array.isArray(b.items_snapshot)) {
            return b.items_snapshot.some(item => item._auth_code && item._auth_code.toUpperCase() === cleanCode);
          }
          return false;
        });
      }
    }

    // 3. Fallback: If numeric ID was searched
    if (!bill && /^\d+$/.test(cleanCode)) {
      const { data: byId } = await supabase
        .from('pharmacy_bills')
        .select('*')
        .eq('id', Number(cleanCode))
        .maybeSingle();
      if (byId) bill = byId;
    }

    if (!bill) {
      return res.status(404).json({
        verified: false,
        code: cleanCode,
        error: `Receipt Not Found. No clinic record matches Auth Code: ${cleanCode}`
      });
    }

    const cleanItems = (bill.items_snapshot || []).filter(item => !item._auth_code);

    res.json({
      verified: true,
      bill: {
        id: bill.id,
        auth_code: bill.auth_code || cleanCode,
        patient_names: bill.patient_names,
        patient_phone: bill.patient_phone || 'Not recorded',
        doctor_name: bill.doctor_name || 'Consulting Physician',
        bill_status: bill.bill_status,
        calculated_total: bill.calculated_total,
        final_total: bill.final_total,
        total_medicine_cost: bill.total_medicine_cost,
        items_snapshot: cleanItems,
        created_by: bill.created_by || 'Counter',
        created_at: bill.created_at
      }
    });
  } catch (err) {
    console.error('Verify bill error:', err);
    res.status(500).json({ error: 'Failed to verify bill record.' });
  }
});

// ============================================================================
// GRN ROUTE 1: Universal Login (Rate-Limited + Issues JWT)
// ============================================================================
app.post('/api/grn/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Credentials required.' });

    const [adminRes, docRes, counterRes] = await Promise.all([
      supabase.from('admin_master').select('*').eq('username', username.trim()).eq('flag', 1).maybeSingle(),
      supabase.from('doctors_master').select('*').eq('username', username.trim()).eq('flag', 1).maybeSingle(),
      supabase.from('counter_staff_master').select('*').eq('username', username.trim()).eq('flag', 1).maybeSingle()
    ]);

    let user = adminRes.data || docRes.data || counterRes.data;
    if (!user) return res.status(401).json({ error: 'Invalid credentials.' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials.' });

    const role = adminRes.data ? 'ADMIN' : (docRes.data ? 'DOCTOR' : 'GRN');
    const token = signJWT({
      id: user.id,
      name: user.name,
      username: user.username,
      role
    });

    res.json({
      id: user.id,
      name: user.name,
      username: user.username,
      access: 'GRANTED',
      token
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// GRN ROUTE 2: Delete/Remove Medicine from Catalog (Protected)
// ============================================================================
app.delete('/api/grn/medicines/:id', requireAuth(['GRN', 'ADMIN', 'COUNTER', 'DOCTOR']), async (req, res) => {
  try {
    const medId = req.params.id;

    // First attempt hard delete (for newly created or unreferenced medicines)
    const { error: delError } = await supabase.from('medicines_master').delete().eq('id', medId);

    // If hard delete was blocked (e.g. PostgreSQL FK constraint violation on past prescriptions) or failed,
    // fallback to soft-delete by setting flag = 0 (hides from active catalog and preserves prescription history)
    if (delError) {
      console.warn(`[GRN Medicine Delete] Hard delete blocked for medicine ID ${medId}: ${delError.message}. Performing soft-delete (flag=0)...`);
      const { error: softError } = await supabase
        .from('medicines_master')
        .update({ flag: 0, updated_at: new Date().toISOString() })
        .eq('id', medId);

      if (softError) throw softError;
    }

    res.json({ success: true, message: 'Medicine removed from catalog.' });
  } catch (err) {
    console.error('Error removing medicine:', err);
    res.status(500).json({ error: err.message || 'Failed to remove medicine.' });
  }
});

// ============================================================================
// COUNTER SMS ROUTE: Update Phone & Dispatch SMS (Rate-Limited + Protected)
// ============================================================================
app.post('/api/counter/send-sms', smsLimiter, requireAuth(['COUNTER', 'ADMIN', 'DOCTOR']), async (req, res) => {
  try {
    const {
      bill_id,
      daily_bill_no,
      ticket_ids,
      phone,
      patient_names,
      final_total,
      date_str
    } = req.body;

    if (!phone || !phone.trim()) {
      return res.status(400).json({ error: 'Phone number is required.' });
    }

    const cleanPhone = phone.trim();
    let updatedPatientProfile = false;

    if (bill_id) {
      await supabase
        .from('pharmacy_bills')
        .update({ patient_phone: cleanPhone })
        .eq('id', bill_id);
    }

    if (Array.isArray(ticket_ids) && ticket_ids.length > 0) {
      const { data: tickets } = await supabase
        .from('ticket_master')
        .select('patient_id')
        .in('id', ticket_ids);

      const patientIds = [...new Set((tickets || []).map(t => t.patient_id).filter(Boolean))];

      if (patientIds.length > 0) {
        const { error: patErr } = await supabase
          .from('patients_master')
          .update({ phone: cleanPhone })
          .in('id', patientIds);

        if (!patErr) updatedPatientProfile = true;
      }
    }

    const apiKey = process.env.DIALOG_SMS_API_KEY;
    const senderMask = process.env.DIALOG_SMS_MASK || 'Wellspring';

    if (!apiKey) {
      return res.json({
        success: false,
        gateway_warning: 'Phone saved, but DIALOG_SMS_API_KEY is not set in backend environment variables.',
        updatedPatientProfile
      });
    }

    let formattedPhone = cleanPhone.replace(/\D/g, '');
    if (formattedPhone.startsWith('0') && formattedPhone.length === 10) {
      formattedPhone = '94' + formattedPhone.substring(1);
    }

    const smsMessage =
      `Wellspring Health Care\n` +
      `Bill No: #${daily_bill_no || bill_id}\n` +
      `Date: ${date_str || 'Today'}\n` +
      `Patient: ${patient_names || 'Walk-In'}\n` +
      `Total Paid: Rs. ${Number(final_total || 0).toFixed(2)}\n` +
      `Thank you for visiting Wellspring!`;

    const dialogUrl =
      `https://e-sms.dialog.lk/api/v1/message-via-url/create/url-campaign` +
      `?esmsqk=${encodeURIComponent(apiKey)}` +
      `&list=${encodeURIComponent(formattedPhone)}` +
      `&source_address=${encodeURIComponent(senderMask)}` +
      `&message=${encodeURIComponent(smsMessage)}`;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    try {
      const response = await fetch(dialogUrl, {
        method: 'GET',
        signal: controller.signal
      });
      clearTimeout(timeout);

      const responseText = (await response.text()).trim();

      if (responseText === '1' || response.ok) {
        return res.json({
          success: true,
          updatedPatientProfile
        });
      } else {
        return res.json({
          success: false,
          gateway_warning: `Phone saved, but Dialog rejected SMS (Code: ${responseText}).`,
          updatedPatientProfile
        });
      }
    } catch (networkErr) {
      clearTimeout(timeout);
      return res.json({
        success: false,
        gateway_warning: 'Phone saved, but Dialog SMS gateway timed out or is unreachable.',
        updatedPatientProfile
      });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ----------------------------------------------------------------------------
// 404 Catch-All Handler
// ----------------------------------------------------------------------------
app.use((req, res) => {
  res.status(404).json({ error: `Not Found: ${req.method} ${req.originalUrl}` });
});

// ----------------------------------------------------------------------------
// Global Error Handler
// ----------------------------------------------------------------------------
app.use((err, req, res, next) => {
  console.error('Unhandled server error:', err);
  if (err.message && err.message.startsWith('Not allowed by CORS')) {
    return res.status(403).json({ error: err.message });
  }
  res.status(500).json({ error: err.message || 'Internal server error' });
});

// ----------------------------------------------------------------------------
// AUTOMATED MAINTENANCE: Purge Obsolete Live Alerts (> 24 hours old)
// Strictly targets ONLY the temporary 'counter_alerts' signaling table.
// Real patient records (channeling, patients, tickets, bills) are never touched.
// ----------------------------------------------------------------------------
async function cleanOldCounterAlerts() {
  try {
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

    const { data, error } = await supabase
      .from('counter_alerts')
      .delete()
      .lt('created_at', twentyFourHoursAgo)
      .select('id');

    if (error) {
      console.warn('[Auto-Clean] counter_alerts cleanup note:', error.message);
    } else if (data && data.length > 0) {
      console.log(`[Auto-Clean] Successfully purged ${data.length} obsolete alert(s) (>24h old) from counter_alerts.`);
    }
  } catch (err) {
    console.warn('[Auto-Clean] Non-blocking maintenance warning:', err.message);
  }
}

// Run initial cleanup 5 seconds after server start, then every 6 hours
setTimeout(cleanOldCounterAlerts, 5000);
const cleanAlertsInterval = setInterval(cleanOldCounterAlerts, 6 * 60 * 60 * 1000);

// ----------------------------------------------------------------------------
// Server Listener with Graceful Shutdown
// ----------------------------------------------------------------------------
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`===============================================`);
  console.log(`🚀 Wellspring Backend API running on port ${PORT}`);
  console.log(`🔒 Security: JWT Auth + Rate Limiting Active`);
  console.log(`🌐 Health check: http://localhost:${PORT}/health`);
  console.log(`🧹 Maintenance: Automatic counter_alerts purge active (every 6h)`);
  console.log(`===============================================`);
});

process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: gracefully shutting down HTTP server...');
  clearInterval(cleanAlertsInterval);
  server.close(() => {
    console.log('HTTP server closed cleanly.');
    process.exit(0);
  });
});
