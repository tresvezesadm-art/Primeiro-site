import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';

// Desliga o parser automático do Vercel: precisamos do corpo "cru" da
// requisição pra conferir a assinatura de segurança (x-signature).
export const config = {
  api: { bodyParser: false },
};

// ============================================================
// MAPA: qual produto da Eduzz libera qual curso no Supabase.
// Troque as chaves pelo ID de cada produto (Órbita > Produtos > Meus
// Produtos, o ID aparece embaixo do nome) e o valor pelo "slug" do
// curso correspondente na tabela "cursos" do Supabase.
// ============================================================
const PRODUTO_PARA_CURSO = {
  '3088563': 'pre-edital-cgu',
  '3121125': 'pos-edital-eppgg-ba',
};

function lerCorpoCru(req) {
  return new Promise((resolve, reject) => {
    let dados = '';
    req.on('data', (pedaco) => { dados += pedaco; });
    req.on('end', () => resolve(dados));
    req.on('error', reject);
  });
}

// Tenta achar o ID do produto em vários lugares possíveis do item da fatura.
function idsDoItem(item) {
  const cand = [
    item.productId, item.product_id, item.product && item.product.id,
    item.product && item.product.productId, item.contentId, item.content_id, item.id,
  ];
  return cand.filter((v) => v !== undefined && v !== null && v !== '').map((v) => String(v));
}

function assinaturaValida(corpoCru, assinaturaRecebida, chaveSecreta) {
  if (!assinaturaRecebida || !chaveSecreta) return false;
  const esperada = crypto.createHmac('sha256', chaveSecreta).update(corpoCru).digest('hex');
  // comparação em tempo constante, pra evitar ataques de timing
  const a = Buffer.from(esperada, 'utf8');
  const b = Buffer.from(assinaturaRecebida, 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, erro: 'Método não permitido' });
  }

  const corpoCru = await lerCorpoCru(req);
  const assinaturaRecebida = req.headers['x-signature'];

  if (!assinaturaValida(corpoCru, assinaturaRecebida, process.env.EDUZZ_WEBHOOK_SECRET)) {
    return res.status(401).json({ ok: false, erro: 'Assinatura inválida' });
  }

  let payload;
  try {
    payload = JSON.parse(corpoCru);
  } catch (e) {
    return res.status(400).json({ ok: false, erro: 'JSON inválido' });
  }

  // Evento de verificação da própria Eduzz (usado ao cadastrar/testar a URL).
  // Não precisa fazer nada, só responder 200.
  if (payload.event === 'ping') {
    return res.status(200).json({ ok: true, ping: true });
  }

  // Só nos interessa fatura paga. Outros eventos (aberta, cancelada,
  // reembolsada etc.) são ignorados por enquanto, mas retornam 200
  // pra Eduzz não ficar reenviando.
  if (payload.event !== 'myeduzz.invoice_paid') {
    console.log('eduzz-webhook evento ignorado:', payload.event);
    return res.status(200).json({ ok: true, ignorado: payload.event });
  }

  const dadosFatura = payload.data || {};
  const comprador = dadosFatura.buyer || dadosFatura.student || dadosFatura.customer || dadosFatura.payer || {};
  const email = comprador.email ? String(comprador.email).trim().toLowerCase() : comprador.email;
  const nome = comprador.name;
  const itens = dadosFatura.items || dadosFatura.products || [];

  // Registro pra conferir no Vercel > Logs o que a Eduzz realmente enviou (sem dados pessoais).
  console.log('eduzz-webhook invoice_paid', JSON.stringify({
    chavesData: Object.keys(dadosFatura),
    temEmail: !!email,
    itens: itens.map((i) => ({ chaves: Object.keys(i), ids: idsDoItem(i) })),
  }));

  if (!email) {
    console.log('eduzz-webhook sem e-mail do comprador');
    return res.status(200).json({ ok: false, erro: 'Fatura sem e-mail de comprador' });
  }

  const supabaseAdmin = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );

  const resultados = [];

  for (const item of itens) {
    const idEncontrado = idsDoItem(item).find((id) => PRODUTO_PARA_CURSO[id]);
    const cursoSlug = idEncontrado ? PRODUTO_PARA_CURSO[idEncontrado] : null;
    if (!cursoSlug) {
      console.log('eduzz-webhook produto não mapeado', JSON.stringify(idsDoItem(item)));
      resultados.push({ ids: idsDoItem(item), ignorado: true, motivo: 'produto não mapeado' });
      continue;
    }

    const { data: curso, error: erroCurso } = await supabaseAdmin
      .from('cursos').select('id').eq('slug', cursoSlug).maybeSingle();
    if (erroCurso || !curso) {
      resultados.push({ productId: item.productId, erro: 'curso não encontrado: ' + cursoSlug });
      continue;
    }

    // Já existe conta com esse e-mail?
    let alunoId = null;
    const { data: perfilExistente } = await supabaseAdmin
      .from('perfis').select('id').eq('email', email).maybeSingle();

    if (perfilExistente) {
      alunoId = perfilExistente.id;
    } else {
      // Cria a conta e manda um e-mail de convite pro aluno definir a senha.
      const { data: convite, error: erroConvite } = await supabaseAdmin.auth.admin.inviteUserByEmail(
        email,
        { data: { full_name: nome || '' }, redirectTo: 'https://www.tresvezesadm.com.br/login.html' }
      );
      if (erroConvite) {
        console.log('eduzz-webhook falha ao criar conta:', erroConvite.message);
        resultados.push({ email, erro: 'falha ao criar conta: ' + erroConvite.message });
        continue;
      }
      alunoId = convite.user.id;
    }

    const { error: erroAcesso } = await supabaseAdmin.from('acessos').upsert(
      { aluno_id: alunoId, curso_id: curso.id, ativo: true },
      { onConflict: 'aluno_id,curso_id' }
    );

    resultados.push({ email, curso: cursoSlug, liberado: !erroAcesso, erro: erroAcesso ? erroAcesso.message : null });
  }

  return res.status(200).json({ ok: true, resultados });
}
