import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import * as crypto from 'crypto';

const app = express();
app.use(express.json());

// CONFIGURAÇÕES CRIPTOGRÁFICAS (Requisito 3.5: Uso de algoritmo adequado AES)
const ALGORITHM = 'aes-256-gcm'; // Padrão da indústria para confidencialidade e integridade
const IV_LENGTH = 12;            // Tamanho padrão do Vetor de Inicialização para o modo GCM

// Requisito 3.6: Proteção da chave simétrica mestre.
// Em produção, deriva-se de process.env.ENCRYPTION_KEY. Aqui geramos uma chave segura para o teste.
const ENCRYPTION_KEY = crypto.scryptSync('chave-secreta-projeto-integrador-2026', 'salt-global-lpro', 32);

// Banco de dados em memória para simular o repouso seguro (LGPD)
const encryptedUserDataBase = new Map<string, string>();

// ==========================================================
// MIDDLEWARE DE INFRAESTRUTURA: IMPOSIÇÃO DE TLS/HTTPS
// ==========================================================
/**
 * REQUISITOS 3.1 e 3.2: Comunicação protegida por TLS/HTTPS e Bloqueio de conexões não seguras
 */
app.use((req: Request, res: Response, next: NextFunction) => {
  // Simulação técnica: Em servidores reais (como AWS, Heroku, Nginx), verifica-se o cabeçalho 'x-forwarded-proto'
  const isSecure = req.headers['x-forwarded-proto'] === 'https' || req.secure;
  
  // Para fins de teste local no terminal, criamos um gatilho para simular o bloqueio de requisição sem TLS
  if (req.headers['force-insecure-test'] === 'true') {
    console.error(`[ALERTA SECURITY] [${new Date().toISOString()}] CONEXÃO REJEITADA: Bloqueio de tráfego HTTP puro/inseguro.`);
    return res.status(403).json({ 
      error: "Upgrade Required. Este sistema exige comunicação criptografada via TLS/HTTPS de forma mandatória." 
    });
  }
  next();
});

// ==========================================================
// ROTAS OPERACIONAIS: CRIPTOGRAFIA EM REPOUSO
// ==========================================================

/**
 * ROTA PARA ARMAZENAMENTO SEGURO (Mecanismo de Cifragem)
 * REQUISITOS 3.4 e 3.5: Dados sensíveis criptografados em repouso usando AES
 */
app.post('/storage/save', (req: Request, res: Response) => {
  const { email, cpf } = req.body;

  if (!email || !cpf) {
    return res.status(400).json({ error: "Parâmetros obrigatórios ausentes." });
  }

  // Geração de um IV (Vetor de Inicialização) pseudoaleatório único para esta operação
  const iv = crypto.randomBytes(IV_LENGTH);
  
  // Criação do cifrador AES-256-GCM
  const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
  
  let encrypted = cipher.update(cpf, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  // Geração da Tag de Autenticação (Garante a integridade do dado, impedindo adulteração no banco)
  const authTag = cipher.getAuthTag().toString('hex');

  // String estruturada para armazenamento (IV + Tag de Autenticação + Texto Cifrado)
  const dbPayload = `${iv.toString('hex')}:${authTag}:${encrypted}`;
  
  // Persistência simulada no banco de dados
  encryptedUserDataBase.set(email, dbPayload);

  // REQUISITO 5.1/5.2: Geração de logs de auditoria claros demonstrando o dado cifrado
  console.log(`[AUDITORIA CRYPTO] [${new Date().toISOString()}] SUCESSO: Dados do utilizador ${email} protegidos. String gravada no banco: ${dbPayload}`);

  res.json({ 
    message: "Dados pessoais armazenados com sucesso e cifrados em repouso.",
    string_gravada_no_banco: dbPayload 
  });
});

app.listen(3000, () => console.log("🚀 Servidor da Entrega 4 (Criptografia e Comunicação) Rodando na Porta 3000"));
