# Central de Monitoramento Vetti — v2

Receptor TCP/IP Contact ID para central **Vetti Smart Alarm Monitorada**, com:

- Decodificacao do protocolo proprietario Vetti (descoberto via proxy MITM)
- Notificacoes push (Pushover) e email (Gmail) por evento
- **Rotacao automatica do `eventos.log`**: quando ultrapassa 300 KB o arquivo
  e enviado por email como anexo e em seguida apagado
- Servidor HTTP minimo de healthcheck para o Render

## Estrutura

```
v2/
  contactid-server.js   # servidor principal (TCP + HTTP)
  package.json
  .env.example          # template de variaveis de ambiente
  .gitignore
  README.md
```

## Variaveis de ambiente

Copie `.env.example` para `.env` e preencha. Resumo:

| Var | Padrao | Descricao |
|---|---|---|
| `PORT` | `10000` | Porta HTTP (Render injeta automatico) |
| `TCP_PORT` | `3013` | Porta TCP onde a central se conecta |
| `HOST` | `0.0.0.0` | Bind address |
| `LOG_FILE` | `eventos.log` | Caminho do log |
| `LOG_MAX_BYTES` | `307200` | Tamanho maximo (300 KB) antes de rotacionar |
| `PUSHOVER_TOKEN` | — | Token da app Pushover |
| `PUSHOVER_USER` | — | User key Pushover |
| `MAIL_USER` | — | Gmail (usuario) |
| `MAIL_PASS` | — | Senha de app do Gmail |
| `MAIL_FROM` | `MAIL_USER` | Remetente |
| `MAIL_TO` | — | Destinatario das notificacoes de evento |
| `MAIL_LOG_TO` | `MAIL_TO` | Destinatario do log rotacionado |
| `EVENTS_IGNORE` | `1141,1602` | QEVTs ignorados |
| `EVENTS_ALERT` | `1130,3130,1309` | QEVTs com push prio alta |
| `EVENTS_MAIL` | `1130,3130` | QEVTs que disparam email |

## Rodar localmente

```powershell
cd v2
npm install
# crie um arquivo .env (copie de .env.example) e preencha
node contactid-server.js
```

A central Vetti deve apontar para `IP_DA_MAQUINA:3013`.

Endpoints HTTP:
- `GET /`     -> JSON com status do servidor
- `GET /log`  -> conteudo atual do `eventos.log` em texto puro

## Rotacao do log

Cada vez que um evento e gravado, o servidor verifica se `eventos.log`
ultrapassou `LOG_MAX_BYTES` (300 KB por padrao). Se sim:

1. O arquivo e renomeado para `eventos-YYYY-MM-DDTHH-MM-SS-mmmZ.log`
2. Um email com o anexo e enviado para `MAIL_LOG_TO`
3. Apos a confirmacao do envio, o arquivo rotacionado e apagado
4. Um novo `eventos.log` vazio comeca a ser preenchido

Se as credenciais de email nao estiverem configuradas, a rotacao apenas
loga um aviso e **nao** apaga o arquivo (para evitar perda de dados).

## Deploy no Render

> **AVISO IMPORTANTE sobre TCP no Render**
>
> O Render Web Service **so expoe trafego HTTP** para a internet publica
> ([docs](https://render.com/docs/web-services)). A central Vetti precisa
> conectar via TCP bruto na porta 3013 — isso **nao e roteavel** atraves
> do proxy HTTP do Render.
>
> O servidor inclui um endpoint HTTP em `PORT` (atendendo o healthcheck
> do Render), mas o socket TCP em `TCP_PORT` so sera alcancavel se a
> central estiver na mesma rede privada do servico (improvavel).
>
> **Solucoes recomendadas:**
> - Usar [Fly.io](https://fly.io) (suporta TCP publico via `[[services.ports]]`)
> - Usar [Railway](https://railway.app) (suporta TCP via `RAILWAY_TCP_PROXY_PORT`)
> - Usar uma VPS (DigitalOcean, Hetzner, Oracle Cloud Free Tier)
> - Manter um tunel TCP (ex.: `ngrok tcp 3013`, `cloudflared`) apontando
>   para uma maquina local que rode o servidor

### Passo a passo (caso voce ainda queira tentar Render)

1. Suba o conteudo da pasta `v2/` para um repositorio Git no GitHub.

2. No [Render Dashboard](https://dashboard.render.com), clique em
   **New > Web Service**, conecte o repo e configure:

   | Campo | Valor |
   |---|---|
   | **Language** | Node |
   | **Build Command** | `npm install` |
   | **Start Command** | `node contactid-server.js` |
   | **Root Directory** | `v2` (se o repo contiver outros diretorios) |

3. Em **Advanced > Environment Variables**, adicione (pelo menos):
   - `PUSHOVER_TOKEN`
   - `PUSHOVER_USER`
   - `MAIL_USER`
   - `MAIL_PASS`
   - `MAIL_FROM`
   - `MAIL_TO`
   - `MAIL_LOG_TO`
   - `LOG_MAX_BYTES` (opcional)
   - `EVENTS_IGNORE`, `EVENTS_ALERT`, `EVENTS_MAIL` (opcional)

4. Adicione um **Persistent Disk** (em Advanced) montado em `/data` se
   quiser que o `eventos.log` sobreviva a deploys. Nesse caso ajuste:
   - `LOG_FILE=/data/eventos.log`

5. Clique em **Create Web Service**. O Render vai detectar a porta HTTP
   em `PORT=10000` e expor `https://<seu-app>.onrender.com`.

6. Acesse `https://<seu-app>.onrender.com/` para validar o JSON de status,
   e `/log` para ver o conteudo atual do log.

## Seguranca

- **NUNCA** commit o `.env` real no Git (ele esta no `.gitignore`).
- Para Gmail use **senha de app** (https://myaccount.google.com/apppasswords),
  nunca a senha principal.
- Considere trocar as credenciais que estavam hardcoded na v1 — elas
  ja foram expostas no historico do projeto.

## Self-test

Ao iniciar, o servidor roda 8 testes com pacotes capturados via proxy MITM
contra `sekron.evtiris.app:6898` e aborta se algum falhar. Se ver

```
self-test OK | handshake
self-test OK | evento compacto (teste periodico 1602)
...
```

esta tudo certo.
