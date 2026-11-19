
require("dotenv").config();

const path = require("path");
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const { MONGO_URI, JWT_SECRET, PORT = 3000 } = process.env;

if (!MONGO_URI || !JWT_SECRET) {
  console.error(
    "Defina MONGO_URI e JWT_SECRET no arquivo .env."
  );
  process.exit(1);
}

// ---------- App ----------
const app = express();

app.use(cors());
app.use(express.json({ limit: "100kb" }));

app.use(
  express.static(path.join(__dirname, "..", "stok_int_front"))
);

// ---------- Conexão MongoDB ----------
mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log("Conectado ao MongoDB.");
  })
  .catch((e) => {
    console.error("Falha ao conectar no MongoDB:", e.message);
    process.exit(1);
  });

// ---------- Configurações ----------
const opcoesJSON = {
  virtuals: true,
  versionKey: false,
  transform: (_doc, ret) => {
    delete ret._id;
    delete ret.senhaHash;
    delete ret.usuarioLower;
  },
};

// ---------- Modelos ----------

const usuarioSchema = new mongoose.Schema(
  {
    usuario: {
      type: String,
      required: true,
      trim: true,
    },

    usuarioLower: {
      type: String,
      required: true,
      unique: true,
    },

    senhaHash: {
      type: String,
      required: true,
    },
  },
  {
    timestamps: true,
    toJSON: opcoesJSON,
  }
);

const Usuario = mongoose.model("Usuario", usuarioSchema);

const produtoSchema = new mongoose.Schema(
  {
    nome: {
      type: String,
      required: true,
      trim: true,
    },

    preco: {
      type: Number,
      required: true,
      min: 0,
    },

    qtd: {
      type: Number,
      required: true,
      min: 0,
    },
  },
  {
    timestamps: true,
    toJSON: opcoesJSON,
  }
);

const Produto = mongoose.model("Produto", produtoSchema);

// ---------- Funções auxiliares ----------

const rota = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const erro = (res, status, texto) =>
  res.status(status).json({ erro: texto });

const gerarToken = (usuario) =>
  jwt.sign(
    { id: usuario.id },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

// ---------- Autenticação ----------

async function autenticar(req, res, next) {
  try {
    const cab = req.headers.authorization || "";

    const token = cab.startsWith("Bearer ")
      ? cab.slice(7)
      : null;

    if (!token) {
      return erro(res, 401, "Não autenticado.");
    }

    const { id } = jwt.verify(token, JWT_SECRET);

    const usuario = await Usuario.findById(id);

    if (!usuario) {
      return erro(res, 401, "Sessão inválida.");
    }

    req.usuario = usuario;

    next();

  } catch (e) {
    return erro(res, 401, "Sessão inválida ou expirada.");
  }
}

// ---------- Criar usuário ----------

async function criarUsuario(usuario, senha) {
  usuario = String(usuario || "").trim();
  senha = String(senha || "");

  if (usuario.length < 3) {
    return {
      erro: "O usuário precisa ter ao menos 3 caracteres.",
    };
  }

  if (senha.length < 4) {
    return {
      erro: "A senha precisa ter ao menos 4 caracteres.",
    };
  }

  const usuarioLower = usuario.toLowerCase();

  const existe = await Usuario.exists({ usuarioLower });

  if (existe) {
    return {
      erro: "Esse usuário já existe.",
    };
  }

  try {
    const doc = await Usuario.create({
      usuario,
      usuarioLower,
      senhaHash: await bcrypt.hash(senha, 10),
    });

    return { doc };

  } catch (e) {
    if (e.code === 11000) {
      return {
        erro: "Esse usuário já existe.",
      };
    }

    throw e;
  }
}

// ======================================
// ROTAS DE AUTENTICAÇÃO
// ======================================

// Verificar se existem usuários cadastrados
app.get(
  "/api/auth/status",
  rota(async (_req, res) => {
    const quantidade = await Usuario.estimatedDocumentCount();

    res.json({
      temUsuarios: quantidade > 0,
    });
  })
);

// Registrar primeiro usuário
app.post(
  "/api/auth/registro",
  rota(async (req, res) => {
    const { usuario, senha } = req.body || {};

    const r = await criarUsuario(usuario, senha);

    if (r.erro) {
      return erro(res, 400, r.erro);
    }

    res.status(201).json({
      token: gerarToken(r.doc),
      usuario: r.doc.usuario,
    });
  })
);

// Login
app.post(
  "/api/auth/login",
  rota(async (req, res) => {
    const { usuario, senha } = req.body || {};

    const doc = await Usuario.findOne({
      usuarioLower: String(usuario || "")
        .trim()
        .toLowerCase(),
    });

    const ok =
      doc &&
      (await bcrypt.compare(
        String(senha || ""),
        doc.senhaHash
      ));

    if (!ok) {
      return erro(
        res,
        401,
        "Usuário ou senha incorretos."
      );
    }

    res.json({
      token: gerarToken(doc),
      usuario: doc.usuario,
    });
  })
);

// Verificar usuário logado
app.get(
  "/api/auth/eu",
  autenticar,
  (req, res) => {
    res.json({
      usuario: req.usuario.usuario,
    });
  }
);

// ======================================
// ROTAS DE PRODUTOS
// ======================================

// Listar produtos
app.get(
  "/api/produtos",
  autenticar,
  rota(async (_req, res) => {
    const produtos = await Produto.find().sort({
      createdAt: 1,
    });

    res.json(produtos);
  })
);

// Cadastrar produto
app.post(
  "/api/produtos",
  autenticar,
  rota(async (req, res) => {
    const nome = String(req.body.nome || "").trim();
    const preco = Number(req.body.preco);
    const qtd = Number(req.body.qtd);

    if (!nome) {
      return erro(
        res,
        400,
        "Informe o nome do produto."
      );
    }

    if (!Number.isFinite(preco) || preco < 0) {
      return erro(
        res,
        400,
        "Informe um preço válido."
      );
    }

    if (!Number.isInteger(qtd) || qtd < 0) {
      return erro(
        res,
        400,
        "Informe uma quantidade válida."
      );
    }

    const produto = await Produto.create({
      nome,
      preco,
      qtd,
    });

    res.status(201).json(produto);
  })
);

// Excluir produto
app.delete(
  "/api/produtos/:id",
  autenticar,
  rota(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return erro(res, 400, "ID inválido.");
    }

    const produto = await Produto.findByIdAndDelete(
      req.params.id
    );

    if (!produto) {
      return erro(res, 404, "Produto não encontrado.");
    }

    res.status(204).end();
  })
);

// ======================================
// ROTAS DE USUÁRIOS
// ======================================

// Listar usuários
app.get(
  "/api/usuarios",
  autenticar,
  rota(async (_req, res) => {
    const usuarios = await Usuario.find().sort({
      createdAt: 1,
    });

    res.json(usuarios);
  })
);

// Cadastrar usuário
app.post(
  "/api/usuarios",
  autenticar,
  rota(async (req, res) => {
    const r = await criarUsuario(
      req.body.usuario,
      req.body.senha
    );

    if (r.erro) {
      return erro(res, 400, r.erro);
    }

    res.status(201).json(r.doc);
  })
);

// Excluir usuário
app.delete(
  "/api/usuarios/:id",
  autenticar,
  rota(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return erro(res, 400, "ID inválido.");
    }

    if (req.params.id === req.usuario.id) {
      return erro(
        res,
        400,
        "Você não pode remover a si mesmo."
      );
    }

    const usuario = await Usuario.findByIdAndDelete(
      req.params.id
    );

    if (!usuario) {
      return erro(res, 404, "Usuário não encontrado.");
    }

    res.status(204).end();
  })
);

// ======================================
// TRATAMENTO DE ROTAS E ERROS
// ======================================

// Rota não encontrada
app.use("/api", (_req, res) => {
  erro(res, 404, "Rota não encontrada.");
});

// Erros gerais
app.use((err, _req, res, _next) => {
  console.error("Erro no servidor:", err);

  erro(
    res,
    500,
    "Erro interno do servidor."
  );
});

// ======================================
// INICIAR SERVIDOR
// ======================================

app.listen(PORT, () => {
  console.log(`Servidor em http://localhost:${PORT}`);
});
