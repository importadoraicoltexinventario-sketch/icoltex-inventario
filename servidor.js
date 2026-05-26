const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { MongoClient, ObjectId } = require('mongodb');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// ── MongoDB ────────────────────────────────────────────────────────────────
const MONGO_URL = process.env.MONGODB_URI || 'mongodb+srv://importadoraicoltexinventario_db_user:inventario@cluster0.jnyrjvm.mongodb.net/icoltex?appName=Cluster0';
let db;

MongoClient.connect(MONGO_URL).then(client => {
  db = client.db('icoltex');
  db.collection('usuarios').createIndex({ email: 1 }, { unique: true });
  db.collection('recuentos').createIndex({ nombre: 1 }, { unique: true });
  db.collection('calendario').createIndex({ clave: 1 }, { unique: true });
  console.log('✅ MongoDB conectado');

  // Crear admin si no existe
  db.collection('usuarios').countDocuments().then(count => {
    console.log('Usuarios en DB:', count);
    if (count === 0) {
      const hash = bcrypt.hashSync('admin123', 10);
      db.collection('usuarios').insertOne({
        nombre: 'Administrador Principal',
        email: 'admin@empresa.com',
        hash, rol: 'admin', ops: [],
        creado: new Date().toISOString()
      }).then(() => console.log('✅ Admin creado: admin@empresa.com'));
    }
  });
}).catch(err => {
  console.error('❌ Error MongoDB:', err);
  process.exit(1);
});

// ── Middlewares ────────────────────────────────────────────────────────────
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  res.header('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

app.use(session({
  secret: process.env.SESSION_SECRET || 'icoltex-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 8 * 60 * 60 * 1000, sameSite: 'lax' }
}));

app.use(express.static(path.join(__dirname, 'public')));

// ── WebSocket ──────────────────────────────────────────────────────────────
const clientes = new Map();

wss.on('connection', (ws) => {
  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg);
      if (data.tipo === 'registro') {
        clientes.set(String(data.userId), ws);
        ws.userId = String(data.userId);
        db.collection('notificaciones').find({ paraId: data.userId, leida: false }).sort({ creado: -1 }).toArray().then(docs => {
          if (docs && docs.length) ws.send(JSON.stringify({ tipo: 'notificaciones_pendientes', datos: docs }));
        });
      }
    } catch(e) {}
  });
  ws.on('close', () => { if (ws.userId) clientes.delete(ws.userId); });
});

function enviarNotificacion(paraId, deId, deNombre, tipo, mensaje) {
  const notif = { paraId, deId, deNombre, tipo, mensaje, leida: false, creado: new Date().toISOString() };
  db.collection('notificaciones').insertOne(notif).then(result => {
    const ws = clientes.get(String(paraId));
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ tipo: 'nueva_notificacion', datos: { ...notif, _id: result.insertedId } }));
    }
  });
}

function broadcast(mensaje) {
  const data = JSON.stringify(mensaje);
  clientes.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) ws.send(data);
  });
}

// ── Auth ───────────────────────────────────────────────────────────────────
const auth = (req, res, next) => req.session.usuario ? next() : res.status(401).json({ error: 'No autorizado' });
const soloAdmin = (req, res, next) => req.session.usuario?.rol === 'admin' ? next() : res.status(403).json({ error: 'Solo admin' });

// ── API Login ──────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Faltan campos' });
  try {
    const todos = await db.collection('usuarios').find({}).toArray();
    console.log('Total usuarios:', todos.length);
    const u = todos.find(x => x.email === email.toLowerCase());
    console.log('Buscando:', email.toLowerCase(), '| Encontrado:', u ? 'SI' : 'NO');
    if (!u) return res.status(401).json({ error: 'Credenciales incorrectas' });
    const ok = bcrypt.compareSync(password, u.hash);
    if (!ok) return res.status(401).json({ error: 'Credenciales incorrectas' });
    const user = { id: u._id.toString(), nombre: u.nombre, email: u.email, rol: u.rol, ops: u.ops || [] };
    req.session.usuario = user;
    res.json({ ok: true, usuario: user });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ ok: true }); });

app.get('/api/sesion', (req, res) => {
  req.session.usuario ? res.json({ usuario: req.session.usuario }) : res.status(401).json({ error: 'Sin sesión' });
});

// ── Usuarios ───────────────────────────────────────────────────────────────
app.get('/api/usuarios', auth, soloAdmin, async (req, res) => {
  const docs = await db.collection('usuarios').find({}, { projection: { hash: 0 } }).toArray();
  res.json(docs.map(u => ({ ...u, id: u._id.toString() })));
});

app.post('/api/usuarios', auth, soloAdmin, async (req, res) => {
  const { nombre, email, password, rol, ops } = req.body;
  const hash = bcrypt.hashSync(password, 10);
  try {
    const result = await db.collection('usuarios').insertOne({ nombre, email: email.toLowerCase(), hash, rol, ops: ops||[], creado: new Date().toISOString() });
    res.json({ ok: true, id: result.insertedId.toString() });
  } catch(err) { res.status(400).json({ error: 'Email ya existe' }); }
});

app.put('/api/usuarios/:id', auth, soloAdmin, async (req, res) => {
  const { nombre, email, password, rol, ops } = req.body;
  const update = { nombre, email: email.toLowerCase(), rol, ops: ops||[] };
  if (password) update.hash = bcrypt.hashSync(password, 10);
  try {
    await db.collection('usuarios').updateOne({ _id: new ObjectId(req.params.id) }, { $set: update });
    res.json({ ok: true });
  } catch(err) { res.status(400).json({ error: err.message }); }
});

app.delete('/api/usuarios/:id', auth, soloAdmin, async (req, res) => {
  await db.collection('usuarios').deleteOne({ _id: new ObjectId(req.params.id) });
  res.json({ ok: true });
});

// ── Recuentos ──────────────────────────────────────────────────────────────
app.get('/api/recuentos', auth, async (req, res) => {
  let recuentos = await db.collection('recuentos').find({}).sort({ creadoEn: -1 }).toArray();
  recuentos = recuentos.map(r => ({ ...r, id: r._id.toString() }));
  if (req.session.usuario.rol === 'operador') {
    const ops = req.session.usuario.ops || [];
    recuentos = recuentos.filter(r => ops.includes(r.nombre));
  }
  res.json(recuentos);
});

app.post('/api/recuentos', auth, soloAdmin, async (req, res) => {
  const { nombre, fecha, almacen, articulos, operadoresIds } = req.body;
  const nuevo = { nombre, fecha, almacen: almacen||'P01', articulos: articulos||[], comentarios: [], creadoEn: new Date().toISOString() };
  try {
    const result = await db.collection('recuentos').insertOne(nuevo);
    if (operadoresIds && operadoresIds.length) {
      for (const uid of operadoresIds) {
        const u = await db.collection('usuarios').findOne({ _id: new ObjectId(uid) });
        if (!u) continue;
        const ops = u.ops || [];
        if (!ops.includes(nombre)) ops.push(nombre);
        await db.collection('usuarios').updateOne({ _id: new ObjectId(uid) }, { $set: { ops } });
        enviarNotificacion(uid, req.session.usuario.id, req.session.usuario.nombre,
          'nuevo_recuento', `📋 Se te asignó el recuento "${nombre}"`);
      }
    }
    res.json({ ok: true, id: result.insertedId.toString() });
  } catch(err) { res.status(400).json({ error: 'Ya existe un recuento con ese nombre' }); }
});

app.put('/api/recuentos/:nombre', auth, async (req, res) => {
  const nombre = decodeURIComponent(req.params.nombre);
  const { articulos, fechaConteo, fecha, almacen, comentarios } = req.body;
  const update = {};
  if (articulos !== undefined) update.articulos = articulos;
  if (comentarios !== undefined) update.comentarios = comentarios;
  if (fechaConteo !== undefined) update.fechaConteo = fechaConteo;
  if (req.session.usuario.rol === 'admin') {
    if (fecha !== undefined) update.fecha = fecha;
    if (almacen !== undefined) update.almacen = almacen;
  }
  await db.collection('recuentos').updateOne({ nombre }, { $set: update });
  broadcast({ tipo: 'recuento_actualizado', nombre });
  res.json({ ok: true });
});

app.delete('/api/recuentos/:nombre', auth, soloAdmin, async (req, res) => {
  await db.collection('recuentos').deleteOne({ nombre: decodeURIComponent(req.params.nombre) });
  res.json({ ok: true });
});

// ── Notificaciones ─────────────────────────────────────────────────────────
app.get('/api/notificaciones', auth, async (req, res) => {
  const docs = await db.collection('notificaciones').find({ paraId: req.session.usuario.id }).sort({ creado: -1 }).limit(50).toArray();
  res.json(docs.map(n => ({ ...n, id: n._id.toString() })));
});

app.put('/api/notificaciones/leer-todas', auth, async (req, res) => {
  await db.collection('notificaciones').updateMany({ paraId: req.session.usuario.id }, { $set: { leida: true } });
  res.json({ ok: true });
});

app.put('/api/notificaciones/:id/leer', auth, async (req, res) => {
  await db.collection('notificaciones').updateOne({ _id: new ObjectId(req.params.id), paraId: req.session.usuario.id }, { $set: { leida: true } });
  res.json({ ok: true });
});

app.post('/api/notificaciones/aviso-completado', auth, async (req, res) => {
  const { recuento } = req.body;
  const admins = await db.collection('usuarios').find({ rol: 'admin' }).toArray();
  admins.forEach(admin => {
    enviarNotificacion(admin._id.toString(), req.session.usuario.id, req.session.usuario.nombre,
      'conteo_completado', `✅ ${req.session.usuario.nombre} completó el conteo de "${recuento}"`);
  });
  res.json({ ok: true });
});

// ── Calendario ─────────────────────────────────────────────────────────────
app.get('/api/calendario', auth, async (req, res) => {
  const docs = await db.collection('calendario').find({}).toArray();
  const obj = {};
  docs.forEach(d => obj[d.clave] = d.texto);
  res.json(obj);
});

app.put('/api/calendario', auth, soloAdmin, async (req, res) => {
  const { clave, texto } = req.body;
  if (texto) {
    await db.collection('calendario').updateOne({ clave }, { $set: { clave, texto } }, { upsert: true });
  } else {
    await db.collection('calendario').deleteOne({ clave });
  }
  res.json({ ok: true });
});

// ── Frontend ───────────────────────────────────────────────────────────────
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── Arrancar ───────────────────────────────────────────────────────────────
const PUERTO = process.env.PORT || 3000;
server.listen(PUERTO, '0.0.0.0', () => {
  console.log(`\n✅ ICOLTEX Inventario PRO corriendo en puerto ${PUERTO}\n`);
});
