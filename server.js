require("dotenv").config();
const path = require("path");
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const { MONGODB_URI, JWT_SECRET, PORT = 3000 } = process.env;
if (!MONGODB_URI || !JWT_SECRET) {
  console.error("Defina MONGODB_URI e JWT_SECRET no arquivo .env (veja .env.example).");
  process.exit(1);
}

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "..", "stok_int_front/")));


// ---------- Início ----------
mongoose
  .connect(MONGODB_URI)
  .then(() => {
    console.log("Conectado ao MongoDB.");
  })
  .catch((e) => {
    console.error("Falha ao conectar no MongoDB:", e.message);
    process.exit(1);
  });


// ---------- Modelos ----------
const opcoesJSON = {
  virtuals: true,
  versionKey: false,
  transform: (_doc, ret) => {
    delete ret._id;
    delete ret.senhaHash;
    delete ret.usuarioLower;
  },
};

const usuarioSchema = new mongoose.Schema(
  {
    usuario: { type: String, required: true, trim: true },
    usuarioLower: { type: String, required: true, unique: true },
    senhaHash: { type: String, required: true },
  },
  { timestamps: true, toJSON: opcoesJSON }
);
const Usuario = mongoose.model("Usuario", usuarioSchema);

const produtoSchema = new mongoose.Schema(
  {
    nome: { type: String, required: true, trim: true },
    preco: { type: Number, required: true, min: 0 },
    qtd: { type: Number, required: true, min: 0 },
  },
  { timestamps: true, toJSON: opcoesJSON }
);
const Produto = mongoose.model("Produto", produtoSchema);

const rota = (fn) => (req, res, next) => fn(req, res, next).catch(next);
const erro = (res, status, texto) => res.status(status).json({ erro: texto });
const gerarToken = (u) => jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: "7d" });

async function autenticar(req, res, next) {
  try {
    const cab = req.headers.authorization || "";
    const token = cab.startsWith("Bearer ") ? cab.slice(7) : null;
    if (!token) return erro(res, 401, "Não autenticado.");
    const { id } = jwt.verify(token, JWT_SECRET);
    const usuario = await Usuario.findById(id);
    if (!usuario) return erro(res, 401, "Sessão inválida.");
    req.usuario = usuario;
    next();
  } catch {
    erro(res, 401, "Sessão inválida ou expirada.");
  }
}

async function criarUsuario(usuario, senha) {
  usuario = String(usuario || "").trim();
  senha = String(senha || "");
  if (usuario.length < 3) return { erro: "O usuário precisa ter ao menos 3 caracteres." };
  if (senha.length < 4) return { erro: "A senha precisa ter ao menos 4 caracteres." };
  const existe = await Usuario.exists({ usuarioLower: usuario.toLowerCase() });
  if (existe) return { erro: "Esse usuário já existe." };
  try {
    const doc = await Usuario.create({
      usuario,
      usuarioLower: usuario.toLowerCase(),
      senhaHash: await bcrypt.hash(senha, 10),
    });
    return { doc };
  } catch (e) {
    if (e.code === 11000) return { erro: "Esse usuário já existe." };
    throw e;
  }
}

// ---------- Autenticação ----------
app.get("/api/auth/status", rota(async (_req, res) => {
  res.json({ temUsuarios: (await Usuario.estimatedDocumentCount()) > 0 });
}));

app.post("/api/auth/registro", rota(async (req, res) => {
  const { usuario, senha } = req.body;
  const r = await criarUsuario(usuario, senha);
  if (r.erro) return erro(res, 400, r.erro);
  res.status(201).json({ token: gerarToken(r.doc), usuario: r.doc.usuario });
}));

app.post("/api/auth/login", rota(async (req, res) => {
  const { usuario, senha } = req.body;
  const doc = await Usuario.findOne({ usuarioLower: String(usuario || "").trim().toLowerCase() });
  const ok = doc && (await bcrypt.compare(String(senha || ""), doc.senhaHash));
  if (!ok) return erro(res, 401, "Usuário ou senha incorretos.");
  res.json({ token: gerarToken(doc), usuario: doc.usuario });
}));

app.get("/api/auth/eu", autenticar, (req, res) => {
  res.json({ usuario: req.usuario.usuario });
});

// ---------- Produtos ----------
app.get("/api/produtos", autenticar, rota(async (_req, res) => {
  res.json(await Produto.find().sort({ createdAt: 1 }));
}));

app.post("/api/produtos", autenticar, rota(async (req, res) => {
  const nome = String(req.body.nome || "").trim();
  const preco = Number(req.body.preco);
  const qtd = Number(req.body.qtd);
  if (!nome) return erro(res, 400, "Informe o nome do produto.");
  if (!Number.isFinite(preco) || preco < 0) return erro(res, 400, "Informe um preço válido.");
  if (!Number.isInteger(qtd) || qtd < 0) return erro(res, 400, "Informe uma quantidade válida.");
  res.status(201).json(await Produto.create({ nome, preco, qtd }));
}));

app.delete("/api/produtos/:id", autenticar, rota(async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return erro(res, 400, "ID inválido.");
  await Produto.findByIdAndDelete(req.params.id);
  res.status(204).end();
}));

// ---------- Usuários ----------
app.get("/api/usuarios", autenticar, rota(async (_req, res) => {
  res.json(await Usuario.find().sort({ createdAt: 1 }));
}));

app.post("/api/usuarios", autenticar, rota(async (req, res) => {
  const r = await criarUsuario(req.body.usuario, req.body.senha);
  if (r.erro) return erro(res, 400, r.erro);
  res.status(201).json(r.doc);
}));

app.delete("/api/usuarios/:id", autenticar, rota(async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return erro(res, 400, "ID inválido.");
  if (req.params.id === req.usuario.id) return erro(res, 400, "Você não pode remover a si mesmo.");
  await Usuario.findByIdAndDelete(req.params.id);
  res.status(204).end();
}));

// ---------- Erros ----------
app.use("/api", (_req, res) => erro(res, 404, "Rota não encontrada."));
app.use((err, _req, res, _next) => {
  console.error(err);
  erro(res, 500, "Erro interno do servidor.");
});

app.listen(PORT, () => console.log(`Servidor em http://localhost:${PORT}`));