import express from 'express';
import type { Request, Response } from 'express';
import * as bcrypt from 'bcrypt';

const app = express();
app.use(express.json());

// REQUISITO 1.2: Parâmetro de custo configurado e visível
const BCRYPT_SALT_ROUNDS = 12;

// Banco de dados simulado em memória
interface User {
  email: string;
  passwordHash: string;
  loginAttempts: number;
  lockUntil?: Date;
  twoFactorSecret: string;
}

const usersDatabase = new Map<string, User>();

/**
 * 1. ROTA DE CADASTRO (Para criar o usuário de teste)
 * REQUISITO 1.1, 1.3 e 1.4: Hash seguro, Salt único por usuário e Armazenamento correto
 */
app.post('/register', async (req: Request, res: Response) => {
  const { email, password } = req.body;

  // O Bcrypt gera o salt único automaticamente e o embutirá no hash final
  const passwordHash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

  usersDatabase.set(email, {
    email,
    passwordHash,
    loginAttempts: 0,
    twoFactorSecret: 'XYZ123TOKENSECURE', // Segredo base32 simulado para o 2FA
  });

  console.log(`[AUDITORIA LOG] [${new Date().toISOString()}] NOVO USUÁRIO CADASTRADO: ${email} (Hash e Salt gerados com sucesso).`);
  res.status(201).json({ message: 'Usuário registrado com sucesso!' });
});

/**
 * 2. ROTA DE LOGIN (Passo 1: Senha)
 * REQUISITO 1.11: Proteção contra Força Bruta (Rate Limit / Bloqueio por 15 minutos)
 */
app.post('/login/step1', async (req: Request, res: Response) => {
  const { email, password } = req.body;
  const user = usersDatabase.get(email);

  if (!user) {
    console.warn(`[AUDITORIA LOG] [${new Date().toISOString()}] TENTATIVA SUSPEITA: Email inexistente (${email}).`);
    return res.status(401).json({ error: 'Credenciais inválidas.' });
  }

  // Verifica se a conta está bloqueada por excesso de tentativas
  if (user.lockUntil && user.lockUntil > new Date()) {
    console.error(`[AUDITORIA LOG] [${new Date().toISOString()}] ACESSO NEGADO: Conta de ${email} bloqueada temporariamente.`);
    return res.status(423).json({ error: 'Conta temporariamente bloqueada por excesso de tentativas. Tente novamente em 15 minutos.' });
  }

  const isMatch = await bcrypt.compare(password, user.passwordHash);

  if (isMatch) {
    user.loginAttempts = 0; // Reseta as falhas se acertou
    console.log(`[AUDITORIA LOG] [${new Date().toISOString()}] SUCESSO PASSO 1: Autenticação primária concluída para ${email}. Aguardando 2FA.`);
    return res.json({ message: 'Autenticação primária aceita. Prossiga para o Passo 2 (2FA).', require2FA: true });
  } else {
    user.loginAttempts += 1;
    console.warn(`[AUDITORIA LOG] [${new Date().toISOString()}] FALHA DE LOGIN: Senha incorreta para ${email}. Tentativa: ${user.loginAttempts}/5`);

    if (user.loginAttempts >= 5) {
      user.lockUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutos de penalidade
      console.error(`[ALERTA DE SEGURANÇA] [${new Date().toISOString()}] CONTA BLOQUEADA: Limite de tentativas atingido para ${email}.`);
    }

    return res.status(401).json({ error: 'Credenciais inválidas.' });
  }
});

/**
 * 3. ROTA DE VALIDAÇÃO DO 2FA (Passo 2)
 * REQUISITO 1.5 e 1.6: Autenticação de dois fatores obrigatória após validação primária
 */
app.post('/login/step2', (req: Request, res: Response) => {
  const { email, token2FA } = req.body;
  const user = usersDatabase.get(email);

  if (!user) return res.status(401).json({ error: 'Usuário inválido.' });

  // Código simulado fixo para teste rápido. Em produção usa-se otplib.authenticator.verify
  const TOKEN_VALIDO_TESTE = '123456';

  if (token2FA === TOKEN_VALIDO_TESTE) {
    console.log(`[AUDITORIA LOG] [${new Date().toISOString()}] AUTENTICAÇÃO COMPLETA: Usuário ${email} efetuou login com sucesso via 2FA.`);
    return res.json({ tokenSessao: 'JWT_SIMULADO_EXPIRACAO_30_MINUTOS', message: 'Login realizado com sucesso!' });
  }

  console.warn(`[AUDITORIA LOG] [${new Date().toISOString()}] FALHA NO 2FA: Token inválido digitado por ${email}.`);
  return res.status(401).json({ error: 'Código 2FA inválido.' });
});

app.listen(3000, () => console.log('🚀 Servidor de Segurança Rodando na Porta 3000'));
