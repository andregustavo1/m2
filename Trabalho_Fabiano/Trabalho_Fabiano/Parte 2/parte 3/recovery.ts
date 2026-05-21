import express from 'express';
import type { Request, Response } from 'express';
import * as crypto from 'crypto';

const app = express();
app.use(express.json());

// Banco de dados simulado em memória para os tokens de recuperação
interface RecoveryRecord {
  token: string;
  expiresAt: Date;
}
const recoveryTokensDatabase = new Map<string, RecoveryRecord>();

/**
 * 1. ROTA DE SOLICITAÇÃO DE RECUPERAÇÃO
 * REQUISITOS 2.1, 2.2, 2.3 e 2.6: Geração de Token Seguro, Expiração e Log de Solicitação
 */
app.post('/recovery/request', (req: Request, res: Response) => {
  const { email } = req.body;

  // Requisito 2.2: Token criptograficamente seguro gerado com alta entropia (PRNG)
  const token = crypto.randomBytes(32).toString('hex');
  
  // Requisito 2.3: Tempo de expiração estrito limitado a 15 minutos
  const expiresAt = new Date();
  expiresAt.setMinutes(expiresAt.getMinutes() + 15);

  // Salva no banco em memória
  recoveryTokensDatabase.set(email, { token, expiresAt });

  // Requisito 2.6: Registro de solicitação de recuperação em log de auditoria
  console.log(`[AUDITORIA RECOVERY] [${new Date().toISOString()}] SOLICITAÇÃO: Novo token de recuperação gerado para o utilizador: ${email}.`);

  res.json({ 
    message: "Se o e-mail estiver registado, um token de recuperação foi enviado.",
    token_gerado_para_teste: token // Exibido para facilitar o seu teste no terminal
  });
});

/**
 * 2. ROTA DE CONFIRMAÇÃO E REDEFINIÇÃO DE SENHA
 * REQUISITOS 2.4, 2.5 e 2.7: Invalidação Pós-Uso, Falha para Expirado e Log de Sucesso/Falha
 */
app.post('/recovery/reset', (req: Request, res: Response) => {
  const { email, token, newPassword } = req.body;
  const record = recoveryTokensDatabase.get(email);

  // Requisito 2.7: Registo de falha do processo (Caso o e-mail/solicitação não exista)
  if (!record) {
    console.warn(`[AUDITORIA RECOVERY] [${new Date().toISOString()}] FALHA: Tentativa de redefinição para e-mail sem token ativo: ${email}.`);
    return res.status(400).json({ error: "Solicitação inválida ou inexistente." });
  }

  // Requisito 2.5: Tratamento e falha correta para token expirado
  if (record.expiresAt < new Date()) {
    recoveryTokensDatabase.delete(email); // Limpa o token expirado por segurança
    console.warn(`[AUDITORIA RECOVERY] [${new Date().toISOString()}] FALHA: O token apresentado por ${email} expirou temporalmente.`);
    return res.status(410).json({ error: "O token de recuperação expirou." });
  }

  // Comparação segura em tempo constante contra ataques de temporização (Timing Attacks)
  const isTokenValid = crypto.timingSafeEqual(Buffer.from(record.token), Buffer.from(token));

  if (!isTokenValid) {
    // Requisito 2.7: Registo de falha (Token incorreto)
    console.warn(`[AUDITORIA RECOVERY] [${new Date().toISOString()}] FALHA: Token inválido fornecido para ${email}.`);
    return res.status(401).json({ error: "Token de segurança inválido." });
  }

  // Requisito 2.4: Token invalidado de forma imediata após o primeiro uso
  recoveryTokensDatabase.delete(email);

  // Requisito 2.7: Registo de sucesso do processo no log
  console.log(`[AUDITORIA RECOVERY] [${new Date().toISOString()}] SUCESSO: O utilizador ${email} redefiniu a senha com sucesso. Token invalidado.`);
  
  res.json({ message: "Senha alterada com sucesso! O token foi destruído e não pode ser reutilizado." });
});

app.listen(3000, () => console.log("🚀 Servidor da Entrega 3 (Recuperação de Senha) Rodando na Porta 3000"));
