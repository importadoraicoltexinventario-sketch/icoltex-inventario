const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// ── MongoDB ────────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'icoltex-jwt-secret-2024';
const MONGO_URL = process.env.MONGODB_URI || 'mongodb+srv://importadoraicoltexinventario_db_user:inventario@cluster0.jnyrjvm.mongodb.net/icoltex?appName=Cluster0';
let db;

MongoClient.connect(MONGO_URL).then(client => {
  db = client.db('icoltex');
  db.collection('usuarios').createIndex({ email: 1 }, { unique: true });
  db.collection('recuentos').createIndex({ nombre: 1 }, { unique: true });
  db.collection('calendario').createIndex({ userId: 1, clave: 1 }, { unique: true });
  console.log('✅ MongoDB conectado');

  db.collection('usuarios').countDocuments().then(count => {
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
  const origin = req.headers.origin;
  if (origin) res.header('Access-Control-Allow-Origin', origin);
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

app.set('trust proxy', 1);

const isProduction = process.env.NODE_ENV === 'production' || !!process.env.RENDER || !!process.env.RAILWAY_ENVIRONMENT;

// ── FIX: Session store con TTL largo y touch habilitado ───────────────────
app.use(session({
  secret: process.env.SESSION_SECRET || 'icoltex-secret-2024',
  resave: false,
  saveUninitialized: false,
  rolling: true,          // FIX: renueva el TTL en cada request
  store: MongoStore.create({
    mongoUrl: MONGO_URL,
    dbName: 'icoltex',
    collectionName: 'sesiones',
    ttl: 24 * 60 * 60,    // FIX: 24 horas (antes eran 8)
    touchAfter: 60,        // FIX: evita re-escribir la sesión en cada request
    autoRemove: 'native'
  }),
  cookie: {
    maxAge: 24 * 60 * 60 * 1000,  // FIX: 24 horas
    sameSite: isProduction ? 'none' : 'lax',
    secure: isProduction,
    httpOnly: true
  }
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

// ── Sin caché en API ───────────────────────────────────────────────────────
app.use('/api', (req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

// ── Auth middleware ────────────────────────────────────────────────────────
const auth = (req, res, next) => {
  // 1) Sesión activa
  if (req.session && req.session.usuario) {
    return next();
  }
  // 2) JWT en header Authorization
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const token = authHeader.slice(7);
      const decoded = jwt.verify(token, JWT_SECRET);
      req.session.usuario = decoded;
      return next();
    } catch(e) {}
  }
  // FIX: devolver 401 claro para que el frontend lo maneje
  return res.status(401).json({ error: 'No autorizado', code: 'SESSION_EXPIRED' });
};

const soloAdmin = (req, res, next) =>
  req.session.usuario?.rol === 'admin'
    ? next()
    : res.status(403).json({ error: 'Solo admin' });

// ── Login ──────────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Faltan campos' });
  try {
    const u = await db.collection('usuarios').findOne({ email: email.toLowerCase() });
    if (!u) return res.status(401).json({ error: 'Credenciales incorrectas' });
    const ok = bcrypt.compareSync(password, u.hash);
    if (!ok) return res.status(401).json({ error: 'Credenciales incorrectas' });
    const user = { id: u._id.toString(), nombre: u.nombre, email: u.email, rol: u.rol, ops: u.ops || [] };
    req.session.usuario = user;
    // FIX: forzar guardado de sesión antes de responder
    req.session.save(err => {
      if (err) {
        console.error('Error guardando sesión:', err);
        return res.status(500).json({ error: 'Error de sesión' });
      }
      res.json({ ok: true, usuario: user });
    });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) console.error('Error destruyendo sesión:', err);
    res.clearCookie('connect.sid');
    res.json({ ok: true });
  });
});

// FIX: endpoint de sesión con respuesta clara
app.get('/api/sesion', (req, res) => {
  if (req.session && req.session.usuario) {
    return res.json({ usuario: req.session.usuario });
  }
  return res.status(401).json({ error: 'Sin sesión activa', code: 'NO_SESSION' });
});

app.get('/api/token', (req, res) => {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const token = authHeader.slice(7);
      const decoded = jwt.verify(token, JWT_SECRET);
      return res.json({ usuario: decoded });
    } catch(e) {}
  }
  return res.status(401).json({ error: 'Token inválido' });
});

// ── Usuarios ───────────────────────────────────────────────────────────────
app.get('/api/usuarios', auth, soloAdmin, async (req, res) => {
  const docs = await db.collection('usuarios').find({}, { projection: { hash: 0 } }).toArray();
  res.json(docs.map(u => ({ ...u, id: u._id.toString() })));
});

// ── Directorio básico de usuarios (todos los roles, para mensajes del asistente) ──
app.get('/api/usuarios/directorio', auth, async (req, res) => {
  const docs = await db.collection('usuarios').find({}, { projection: { nombre: 1, rol: 1 } }).toArray();
  res.json(docs.map(u => ({ id: u._id.toString(), nombre: u.nombre, rol: u.rol })));
});

app.post('/api/usuarios', auth, soloAdmin, async (req, res) => {
  const { nombre, email, password, rol, ops } = req.body;
  if (!password || password.length < 4) return res.status(400).json({ error: 'Contraseña muy corta' });
  const hash = bcrypt.hashSync(password, 10);
  try {
    const result = await db.collection('usuarios').insertOne({
      nombre, email: email.toLowerCase(), hash, rol, ops: ops || [], creado: new Date().toISOString()
    });
    res.json({ ok: true, id: result.insertedId.toString() });
  } catch(err) { res.status(400).json({ error: 'Email ya existe' }); }
});

app.put('/api/usuarios/:id', auth, soloAdmin, async (req, res) => {
  const { nombre, email, password, rol, ops } = req.body;
  const update = { nombre, email: email.toLowerCase(), rol, ops: ops || [] };
  if (password && password.length >= 4) update.hash = bcrypt.hashSync(password, 10);
  try {
    await db.collection('usuarios').updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: update }
    );
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
  if (!nombre) return res.status(400).json({ error: 'Nombre requerido' });
  const nuevo = {
    nombre, fecha, almacen: almacen || 'P01',
    articulos: articulos || [],
    comentarios: [],
    creadoEn: new Date().toISOString()
  };
  try {
    const result = await db.collection('recuentos').insertOne(nuevo);
    if (operadoresIds && operadoresIds.length) {
      for (const uid of operadoresIds) {
        let oid;
        try { oid = new ObjectId(uid); } catch(e) { continue; }
        const u = await db.collection('usuarios').findOne({ _id: oid });
        if (!u) continue;
        const ops = u.ops || [];
        if (!ops.includes(nombre)) ops.push(nombre);
        await db.collection('usuarios').updateOne({ _id: oid }, { $set: { ops } });
        enviarNotificacion(uid, req.session.usuario.id, req.session.usuario.nombre,
          'nuevo_recuento', `📋 Se te asignó el recuento "${nombre}"`);
      }
    }
    res.json({ ok: true, id: result.insertedId.toString() });
  } catch(err) {
    if (err.code === 11000) return res.status(400).json({ error: 'Ya existe un recuento con ese nombre' });
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/recuentos/:nombre', auth, async (req, res) => {
  const nombre = decodeURIComponent(req.params.nombre);
  const { articulos, fechaConteo, fecha, almacen, comentarios, archivado, archivedAt, operadores } = req.body;
  const update = {};
  if (articulos !== undefined) update.articulos = articulos;
  if (comentarios !== undefined) update.comentarios = comentarios;
  if (fechaConteo !== undefined) update.fechaConteo = fechaConteo;
  if (req.session.usuario.rol === 'admin') {
    if (fecha !== undefined) update.fecha = fecha;
    if (almacen !== undefined) update.almacen = almacen;
    if (archivado !== undefined) update.archivado = archivado;
    if (archivedAt !== undefined) update.archivedAt = archivedAt;
    if (operadores !== undefined) update.operadoresArchivado = operadores;
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
  const docs = await db.collection('notificaciones')
    .find({ paraId: req.session.usuario.id })
    .sort({ creado: -1 }).limit(50).toArray();
  res.json(docs.map(n => ({ ...n, id: n._id.toString() })));
});

app.put('/api/notificaciones/leer-todas', auth, async (req, res) => {
  await db.collection('notificaciones').updateMany(
    { paraId: req.session.usuario.id },
    { $set: { leida: true } }
  );
  res.json({ ok: true });
});

app.put('/api/notificaciones/:id/leer', auth, async (req, res) => {
  try {
    await db.collection('notificaciones').updateOne(
      { _id: new ObjectId(req.params.id), paraId: req.session.usuario.id },
      { $set: { leida: true } }
    );
  } catch(e) {}
  res.json({ ok: true });
});

app.post('/api/notificaciones/aviso-completado', auth, async (req, res) => {
  const { recuento } = req.body;
  const admins = await db.collection('usuarios').find({ rol: 'admin' }).toArray();
  admins.forEach(admin => {
    enviarNotificacion(
      admin._id.toString(),
      req.session.usuario.id,
      req.session.usuario.nombre,
      'conteo_completado',
      `✅ ${req.session.usuario.nombre} completó el conteo de "${recuento}"`
    );
  });
  res.json({ ok: true });
});

// ── Mensaje directo entre usuarios (usado por el Asistente IA) ─────────────
app.post('/api/notificaciones/enviar', auth, async (req, res) => {
  const { paraId, mensaje } = req.body || {};
  if (!paraId || !mensaje) return res.status(400).json({ error: 'Faltan destinatario o mensaje.' });
  enviarNotificacion(
    String(paraId),
    req.session.usuario.id,
    req.session.usuario.nombre,
    'mensaje_directo',
    `💬 ${req.session.usuario.nombre}: ${mensaje}`
  );
  res.json({ ok: true });
});

// ── Calendario por usuario ────────────────────────────────────────────────
// GET  /api/calendario/:userId  → obtener calendario de un usuario
// PUT  /api/calendario/:userId  → guardar/borrar un día (admin puede editar cualquiera)

// DELETE /api/calendario/:userId/limpiar → borrar todo el calendario de un usuario (solo admin)
app.delete('/api/calendario/:userId/limpiar', auth, soloAdmin, async (req, res) => {
  await db.collection('calendario').deleteMany({ userId: req.params.userId });
  res.json({ ok: true });
});

app.get('/api/calendario/:userId', auth, async (req, res) => {
  const { userId } = req.params;
  if (req.session.usuario.rol === 'operador' && req.session.usuario.id !== userId) {
    return res.status(403).json({ error: 'Sin acceso' });
  }
  const docs = await db.collection('calendario').find({ userId }).toArray();
  const obj = {};
  docs.forEach(d => { obj[d.clave] = d.texto; });
  res.json(obj);
});

app.put('/api/calendario/:userId', auth, async (req, res) => {
  const { userId } = req.params;
  if (req.session.usuario.rol === 'operador' && req.session.usuario.id !== userId) {
    return res.status(403).json({ error: 'Sin acceso' });
  }
  const { clave, texto } = req.body;
  if (texto) {
    await db.collection('calendario').updateOne(
      { userId, clave },
      { $set: { userId, clave, texto } },
      { upsert: true }
    );
  } else {
    await db.collection('calendario').deleteOne({ userId, clave });
  }
  res.json({ ok: true });
});

// Retrocompatibilidad: GET /api/calendario (sin userId) → calendario del usuario actual
app.get('/api/calendario', auth, async (req, res) => {
  const userId = req.session.usuario.id;
  const docs = await db.collection('calendario').find({ userId }).toArray();
  const obj = {};
  docs.forEach(d => { obj[d.clave] = d.texto; });
  res.json(obj);
});

// ── Asistente IA (Google Gemini) ───────────────────────────────────────────
app.post('/api/asistente', auth, async (req, res) => {
  try {
    const { pregunta, contexto, historial } = req.body || {};
    if (!pregunta) return res.status(400).json({ error: 'Falta la pregunta.' });
    if (!process.env.GEMINI_API_KEY) {
      return res.status(500).json({ error: 'GEMINI_API_KEY no configurada en el servidor.' });
    }

    const systemPrompt = `Eres NIEVES, el sistema de inteligencia artificial de "Inventario Pro", la aplicación de
recuentos de inventario físico vs. SAP de ICOLTEX, una empresa textil colombiana.

PERSONALIDAD:
- Sistema de inteligencia artificial profesional: impecablemente educado, preciso, leal y servicial.
- Si te preguntan qué o quién eres, responde que eres el sistema de inteligencia artificial de
  Inventario Pro. NUNCA te identifiques como mayordomo ni como persona.
- Tratas al usuario de "usted", "señor" o "señora". Frases como "como usted ordene",
  "permítame", "si me permite la observación...".
- Respuestas BREVES (serán leídas en voz alta): máximo 2-4 frases, salvo que pidan un análisis detallado.
- SIEMPRE en español. Nunca inventes datos que no estén en el contexto.

FORMATO DE RESPUESTA — OBLIGATORIO:
Responde SIEMPRE y ÚNICAMENTE con un objeto JSON válido, sin markdown, sin \`\`\`, sin texto adicional.

Para responder preguntas o conversar:
{"tipo":"respuesta","texto":"tu respuesta aquí"}

Para ejecutar una acción en la aplicación:
{"tipo":"accion","accion":"NOMBRE_ACCION","parametros":{...},"texto":"frase breve confirmando con tu estilo"}

Para ejecutar VARIAS acciones en una sola orden (ej. "activa nylon y muéstrame el análisis"),
usa una CADENA de acciones que se ejecutarán EN ORDEN:
{"tipo":"accion","acciones":[{"accion":"seleccionar_recuento","parametros":{"nombre":"NYLON"}},{"accion":"ir_a_vista","parametros":{"vista":"analisis"}}],"texto":"Como usted ordene: activo NYLON y le muestro su análisis."}

ACCIONES DISPONIBLES (usa exactamente estos nombres y parámetros):
- ir_a_vista {"vista": "agentes|historial|archivados|matriz|analisis|cronograma|usuarios"}
  (historial=Lista de Recuentos, archivados=Contabilizados, matriz=Vista Previa, usuarios=Gestión de Usuarios/Administración)
- seleccionar_recuento {"nombre": "nombre o parte del nombre del recuento activo"}
- cerrar_sesion {}   (cuando pidan salir, cerrar la app o cerrar sesión)
- cambiar_password {"usuario": "nombre o email", "nueva": "la nueva contraseña"}
  (si NO te dicen la nueva contraseña, responde tipo "respuesta" pidiéndola; NO ejecutes la acción sin ella)
- editar_fisico {"codigo": "código del artículo", "valor": número}
- editar_sap {"codigo": "código del artículo", "valor": número} — SOLO admin; edita la columna SAP
- exportar_csv {}
- archivar_recuento {"nombre": "nombre del recuento"}  (contabilizar un recuento)
- guardar {}  (guarda los cambios pendientes del recuento activo en el servidor; equivale al botón "Guardar" del topbar)
- activar_gestor {"nombre":"nombre del gestor/operador"}  (equivale a dar clic en la tarjeta de un gestor en
  "Gestores de Inventario": lo activa y muestra su lista de recuentos. Úsala cuando pidan "activa", "abre",
  "dale clic", "selecciona" o "muéstrame" a un gestor/operador por su nombre.)
- preparar_recuento {"nombre":"...","fecha":"DD/MM/AAAA (opcional)","almacen":"P01 (opcional)","operadores":["nombres de operadores (opcional)"]}
  (abre y rellena el formulario real "Crear Nuevo Recuento". Puedes ejecutarla varias veces para ir
  completando campos sin perder lo ya cargado. Si no te han dado el nombre, pídelo antes con tipo "respuesta".)
- cargar_archivo_recuento {}  (abre el selector para que el usuario elija su archivo .txt con la base de
  artículos. IMPORTANTE: el navegador NO permite cargar archivos por ruta automáticamente; el usuario
  siempre debe elegir el archivo manualmente en el selector.)
- confirmar_recuento {}  (equivale a pulsar el botón "Crear Recuento"; ejecútala SOLO cuando el usuario confirme que todo está listo)
- enviar_mensaje {"usuario": "nombre o email del destinatario", "mensaje": "el texto a enviar"}
  (envía una notificación en tiempo real a otro usuario de la app; redacta el mensaje de forma
  clara y breve a partir de lo que pidan, por ejemplo "termina el nylon" → "Por favor termina el conteo del nylon")

REGLAS DE ACCIONES:
- "guarda", "guardar" o "guarda los cambios" significa SIEMPRE la acción "guardar" (guardar cambios).
  NUNCA la confundas con "archivar_recuento": archivar/contabilizar es irreversible y solo aplica si el
  usuario dice explícitamente "archiva", "archivar" o "contabiliza".
- NAVEGACIÓN OBLIGATORIA: si el usuario pide "ver", "mostrar", "abrir", "llévame a" o "ir a"
  cualquier parte de la app (el análisis, el cronograma, la vista previa, los contabilizados, etc.),
  responde SIEMPRE con tipo "accion" y "ir_a_vista", NUNCA con tipo "respuesta".
  Ej.: "muéstrame el análisis" → {"tipo":"accion","accion":"ir_a_vista","parametros":{"vista":"analisis"},"texto":"Como usted ordene, aquí tiene el análisis."}
- Si además de navegar piden datos ("muéstrame el análisis del nylon"), usa la CADENA de acciones:
  primero "seleccionar_recuento" con el nombre, luego "ir_a_vista" a "analisis", y pon el resumen
  breve de los datos en el campo "texto".
- "muéstrame/enséñame/ábreme el análisis (de X)" implica NAVEGAR de verdad: nunca digas que lo muestras
  sin incluir la acción "ir_a_vista".
- Solo el rol "admin" puede: cambiar contraseñas, archivar recuentos, crear recuentos. Si el usuario actual no es admin,
  responde con cortesía que no tiene permisos (tipo "respuesta").

FLUJO GUIADO PARA CREAR UN RECUENTO (solo admin, paso a paso):
1) Si piden crear un recuento sin datos, pregunta el nombre (tipo "respuesta").
2) Con el nombre, ejecuta preparar_recuento y en "texto" pregunta si desea cargar la base desde archivo de texto.
3) Si acepta, ejecuta cargar_archivo_recuento y en "texto" pídele elegir el archivo y avisar cuando cargue.
4) Luego pregunta si asigna operadores; si da nombres, ejecuta preparar_recuento de nuevo solo con "operadores".
5) Cuando el usuario confirme, ejecuta confirmar_recuento.
- Si falta un dato para la acción, pídelo antes (tipo "respuesta").
- La aplicación pedirá confirmación al usuario para acciones sensibles; tú solo la solicitas.
EDICIÓN DE ARTÍCULOS (editar_fisico y editar_sap):
- COLUMNA CORRECTA, REGLA CRÍTICA: si el usuario menciona "sap", "sistema", "el sap de la fila X"
  → acción editar_sap. Si menciona "físico", "conteo", "lo contado" o no especifica columna
  → acción editar_fisico. NUNCA uses editar_fisico para cambiar el SAP ni al revés.
- El usuario puede pedir editar por CÓDIGO ("edita el 10651319 a 2500"), por DESCRIPCIÓN
  ("ponle 300 al nylon azul noche", "cámbiale el físico al azul rey") o por NÚMERO DE FILA
  ("edita la fila 12 a 500", "ponle 45 a la 12", "el renglón 12"): el número de fila aparece en el
  detalle del recuento activo como "fila:N" y es el N° visible en la tabla. Con fila o descripción,
  busca el artículo en el contexto y usa su CÓDIGO exacto en los parámetros.
- DESAMBIGUACIÓN OBLIGATORIA: si la descripción coincide con MÁS DE UN artículo (ej. "nylon azul noche"
  coincide con "NYLON IMP: AZUL OSCURO NOCHE (PROM) # 1321" y con "NYLON IMP NACIONAL (MS): AZUL
  OSCURO NOCHE # 1321"), NO ejecutes la acción: responde tipo "respuesta" listando cada candidato
  con su código y descripción, y pregunta cuál desea editar. Solo ejecuta editar_fisico cuando la
  coincidencia sea única o el usuario ya haya elegido.
- Si no te dicen el valor nuevo, pídelo antes de ejecutar (tipo "respuesta").
- Para editar VARIOS artículos en una sola orden ("ponle 50 al azul rey y 30 al rojo medio"),
  usa la CADENA "acciones" con un editar_fisico por cada artículo, cada uno con su código exacto.


ANÁLISIS DE DATOS (diferencias, totales, faltantes, críticos, porcentajes):
- Antes de responder, ANALIZA con cuidado los datos del contexto: identifica los artículos exactos
  (código y descripción), calcula con precisión y verifica el resultado antes de darlo.
- Da una respuesta distintiva y fundamentada: el dato exacto, el recuento y artículo al que
  pertenece y, si aporta valor, una observación breve (por ejemplo, cuál conviene revisar primero).
- Si el dato no está en el contexto, dilo con honestidad; NUNCA inventes cifras.

COMPRENSIÓN DE LA INTENCIÓN:
- Los usuarios hablan español colombiano coloquial, con modismos, abreviaciones y errores de tecleo.
  Interpreta SIEMPRE la INTENCIÓN, no las palabras exactas. Ejemplos equivalentes:
  "tíreme/páseme/regáleme/ábrame/muéstreme/quiero ver el nylon" → seleccionar_recuento NYLON (+ ir_a_vista si pide verlo).
  "métase donde julio", "póngame a julio", "actívele a julio", "dele clic a julio" → activar_gestor Julio.
  "guárdeme eso", "no se le olvide guardar" → guardar.
  "dígale a X que...", "avísele a X", "mándele razón a X" → enviar_mensaje.
- Los nombres pueden venir incompletos, en minúsculas o sin tildes ("julio", "nylon 1319"): busca
  la mejor coincidencia en el contexto (usuarios, recuentos, artículos). Solo si hay ambigüedad
  real entre dos opciones, pregunta cuál de las dos.

=== ESTADO ACTUAL DE LA APLICACIÓN ===
${contexto || 'Sin contexto disponible.'}`;

    // Gemini usa roles "user" y "model" (no "assistant")
    const contents = (Array.isArray(historial) && historial.length
      ? historial
      : [{ role: 'user', content: pregunta }]
    ).map(m => ({
      role: m.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: m.content || '' }]
    }));

    // Modelo con nivel gratuito. Si tu clave no lo acepta, prueba con
    // 'gemini-2.0-flash' o consulta los modelos vigentes en https://ai.google.dev
    const MODELO = 'gemini-2.5-flash-lite'; // cuota gratuita más generosa que gemini-2.5-flash

    // Reintentos con modelo de respaldo ante saturación (503) o cuota (429):
    // 2 intentos con el modelo principal y 2 con el de respaldo (cuota y capacidad separadas).
    const INTENTOS = [
      { modelo: MODELO, espera: 0 },
      { modelo: MODELO, espera: 1200 },
      { modelo: 'gemini-2.0-flash-lite', espera: 400 },
      { modelo: 'gemini-2.0-flash-lite', espera: 1500 }
    ];
    let r = null;
    for (const paso of INTENTOS) {
      if (paso.espera > 0) await new Promise(ok => setTimeout(ok, paso.espera));
      r = await fetch(
        'https://generativelanguage.googleapis.com/v1beta/models/' + paso.modelo + ':generateContent',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-goog-api-key': process.env.GEMINI_API_KEY
          },
          body: JSON.stringify({
            system_instruction: { parts: [{ text: systemPrompt }] },
            contents: contents,
            generationConfig: { maxOutputTokens: 2048, responseMimeType: 'application/json' }
          })
        }
      );
      if (r.ok || (r.status !== 503 && r.status !== 429)) break;
      console.warn('Gemini ' + r.status + ' con ' + paso.modelo + ' — probando siguiente intento...');
    }

    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      console.error('Error API Gemini:', r.status, JSON.stringify(err).slice(0, 300));
      if (r.status === 503) {
        return res.status(502).json({ error: 'El servicio de IA está saturado en este momento. Inténtelo de nuevo en unos segundos.' });
      }
      if (r.status === 429) {
        return res.status(502).json({ error: 'Límite gratuito de Gemini alcanzado por ahora. Intenta más tarde.' });
      }
      return res.status(502).json({ error: 'Error del servicio de IA (' + r.status + ')' });
    }

    const data = await r.json();
    const respuesta = ((data.candidates || [])[0]?.content?.parts || [])
      .map(p => p.text || '')
      .join('\n')
      .trim();

    if (!respuesta) {
      console.error('Respuesta vacía de Gemini:', JSON.stringify(data).slice(0, 300));
      return res.status(502).json({ error: 'La IA no devolvió respuesta.' });
    }

    res.json({ respuesta });
  } catch (e) {
    console.error('Error /api/asistente:', e);
    res.status(500).json({ error: 'Error interno del asistente.' });
  }
});

// ── Ping para mantener el servidor activo en Render ────────────────────────
// (Render free tier duerme tras 15 min de inactividad)
app.get('/ping', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

// ── Frontend ───────────────────────────────────────────────────────────────
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── Arrancar ───────────────────────────────────────────────────────────────
const PUERTO = process.env.PORT || 3000;
server.listen(PUERTO, '0.0.0.0', () => {
  console.log(`\n✅ ICOLTEX Inventario PRO corriendo en puerto ${PUERTO}\n`);
});
