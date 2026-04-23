// contactid-server.js (v2)
// Receptor TCP/IP Contact ID para central Vetti Smart Alarm Monitorada.
//
// Diferencas em relacao a v1:
//   - Tokens, credenciais de email e parametros via process.env
//   - Rotacao automatica do eventos.log: ao atingir LOG_MAX_BYTES o arquivo
//     e enviado por email (igual as notificacoes) e em seguida apagado
//   - Servidor HTTP minimo para healthcheck (necessario para o Render Web Service)
//   - Mantem o servidor TCP/IP em TCP_PORT (compativel com a central Vetti)
//
// Protocolo descoberto via proxy MITM contra o servidor oficial Vetti
// (sekron.evtiris.app:6898). Existem 3 tipos de frame da central -> servidor:
//
//   1) HANDSHAKE/HEARTBEAT (TYPE 0xC0) - 10 bytes
//   2) EVENTO COMPACTO (TYPE 0xC2) - 16 bytes (teste periodico)
//   3) EVENTO CONTACT-ID EXPANDIDO (TYPE 0xC1) - 20 bytes (eventos reais)
//
// ACK do servidor (mesmo para todos os tipos): 5 bytes
//      02 04 [TYPE] 80 [CRC8]
//
// CRC-8 poly 0x07, init 0x00, sem reflexao, sobre LEN..ultimo-byte-antes-do-CRC.

const net = require('net');
const http = require('http');
const fs = require('fs');
const path = require('path');
const https = require('https');
const nodemailer = require('nodemailer');

// ---------- Variaveis de ambiente ----------
const PORT = parseInt(process.env.PORT || '10000', 10);          // HTTP healthcheck (Render)
const TCP_PORT = parseInt(process.env.TCP_PORT || '3013', 10);   // TCP da central Vetti
const HOST = process.env.HOST || '0.0.0.0';
const LOG_FILE = process.env.LOG_FILE || path.join(__dirname, 'eventos.log');
const LOG_MAX_BYTES = parseInt(process.env.LOG_MAX_BYTES || '307200', 10); // 300 KB

const PUSHOVER_TOKEN = process.env.PUSHOVER_TOKEN || '';
const PUSHOVER_USER = process.env.PUSHOVER_USER || '';

const MAIL_USER = process.env.MAIL_USER || '';
const MAIL_PASS = process.env.MAIL_PASS || '';
const MAIL_FROM = process.env.MAIL_FROM || MAIL_USER;
const MAIL_TO = process.env.MAIL_TO || '';
const MAIL_LOG_TO = process.env.MAIL_LOG_TO || MAIL_TO;

const STX = 0x02;
const TYPE_HANDSHAKE = 0xc0;
const TYPE_EVENT_CID = 0xc1;
const TYPE_EVENT_COMPACT = 0xc2;
const ACK_FIXED_BYTE = 0x80;

const eventsToIgnore = (process.env.EVENTS_IGNORE || '1141,1602')
    .split(',').map(s => parseInt(s.trim(), 10)).filter(Boolean);
const eventsToAlert = (process.env.EVENTS_ALERT || '1130,3130,1309')
    .split(',').map(s => parseInt(s.trim(), 10)).filter(Boolean);
const eventsToAlertByMail = (process.env.EVENTS_MAIL || '1130,3130')
    .split(',').map(s => parseInt(s.trim(), 10)).filter(Boolean);

// ---------- CRC-8 (poly 0x07, init 0x00, sem reflexao) ----------
const CRC8_TABLE = (() => {
    const t = new Uint8Array(256);
    for (let i = 0; i < 256; i++) {
        let c = i;
        for (let j = 0; j < 8; j++) {
            c = (c & 0x80) ? ((c << 1) ^ 0x07) & 0xff : (c << 1) & 0xff;
        }
        t[i] = c;
    }
    return t;
})();

function crc8(buf) {
    let c = 0;
    for (const b of buf) c = CRC8_TABLE[c ^ b];
    return c;
}

// ---------- Tabelas de eventos (especificas Vetti Smart Alarm) ----------
// Q=1 -> EVENTO (acionamento/abertura)
// Q=3 -> RESTAURO (fechamento/normalizacao). Na Vetti os restauros tem nome
//         proprio (ex.: 3401 = "Arme", nao "Rest. de desarme") -> tabela separada.
const EVENT_NAMES = {
    120: 'Panico com acionamento de sirene',
    121: 'Coacao',
    122: 'Panico silencioso',
    130: 'Disparo de zona',
    133: 'Disparo de zona 24 horas',
    137: 'Tamper painel aberto',
    141: 'Laco Aberto (sensor abertura aberto)',
    144: 'Tamper sensor aberto',
    146: 'Disparo de zona silenciosa',
    147: 'Falha de comunicacao com o sensor',
    301: 'Falha de AC',
    302: 'Reset da central',
    305: 'Desligamento da central (System shutdown)',
    308: 'Falha no teste de bateria principal',
    309: 'Bateria principal ausente',
    311: 'Reset de fabrica',
    313: 'Sirene com fio ausente',
    321: 'Bateria baixa de sensor sem fio',
    384: 'Bateria baixa em sensor RF',
    401: 'Desarme',
    403: 'Desarme Automatico',
    407: 'Desarme Remoto',
    454: 'Falha Arme',
    530: 'Sensor / Zona Inibida',
    531: 'Dispositivo adicionado',
    532: 'Dispositivo removido',
    570: 'Sensor / Zona Isolada',
    602: 'Teste periodico',
    627: 'Entrada Modo Programacao Painel',
    628: 'Saida Modo Programacao Painel',
    708: 'PGM acionado',
    840: 'Disparo de zona abertura Shox',
    850: 'Disparo de zona Portao',
    860: 'PGM ligado',
    861: 'PGM pulso',
    870: 'Teclado - Tamper Violado',
    871: 'Teclado - Excesso de tentativas com senha invalida',
    872: 'Teclado - Bateria baixa 30%',
    873: 'Teclado - Fonte ausente',
    903: 'Firmware - Download iniciado',
    904: 'Firmware - Falha na atualizacao (interface no byte "particao")',
    905: 'Firmware - Atualizacao concluida (versao/revisao nos bytes "zona/usuario" e "particao")',
};

const RESTORE_NAMES = {
    130: 'Rest. de disparo de zona',
    133: 'Rest. de disparo de zona 24 horas',
    137: 'Rest. de Tamper painel',
    141: 'Rest. de Laco Aberto (sensor de abertura fechado)',
    144: 'Rest. de Tamper sensor',
    146: 'Rest. de disparo de zona silenciosa',
    147: 'Rest. de falha de comunicacao com o sensor',
    301: 'Rest. da falha de AC',
    302: 'Rest. de bateria principal baixa',
    308: 'Rest. de desligamento da central (System shutdown)',
    309: 'Teste de bateria principal OK',
    311: 'Rest. de bateria principal ausente',
    321: 'Rest. sirene com fio ausente',
    384: 'Rest. de bateria baixa de sensor sem fio',
    401: 'Arme',
    403: 'Arme Automatico',
    407: 'Arme Remoto',
    441: 'Arme Stay',
    530: 'Rest. de Sensor / Zona Inibida',
    570: 'Rest. de Sensor / Zona Isolada',
    840: 'Rest. de disparo de zona abertura Shox',
    850: 'Rest. de disparo de zona Portao',
    860: 'PGM desligado',
    870: 'Rest. Teclado - Tamper Violado',
    871: 'Rest. Teclado - Excesso de tentativas de senha invalida',
    872: 'Rest. Teclado - Bateria baixa',
    873: 'Rest. Teclado - Fonte ausente',
    874: 'Restauracao Teclado - Perca de comunicacao',
    903: 'Firmware - Download finalizado (interface utilizada reportada no byte "particao")',
};

function describeEvent(qevt) {
    const q = Math.floor(qevt / 1000);
    const evt = qevt % 1000;
    const table = q === 3 ? RESTORE_NAMES : EVENT_NAMES;
    const name = table[evt] || 'Evento desconhecido';
    const qStr = q === 1 ? 'EVENTO' : q === 3 ? 'RESTAURO' : `Q${q}`;
    return { qevt, q, evt, name, qStr, label: `[${qStr}] ${qevt} - ${name}` };
}

// ---------- Helpers BCD ----------
function nibToDigit(n) {
    if (n === 0x0a) return '0';
    if (n >= 0 && n <= 9) return String(n);
    return '?';
}

function readDigits(buf, offset, n) {
    let s = '';
    for (let i = 0; i < n; i++) {
        s += nibToDigit(buf[offset + i] & 0x0f);
    }
    return s;
}

function readBcdPacked(buf) {
    let s = '';
    for (const b of buf) {
        s += ((b >> 4) & 0xf).toString(16);
        s += (b & 0xf).toString(16);
    }
    return s.toUpperCase();
}

function formatMac(buf) {
    return [...buf].map(b => b.toString(16).padStart(2, '0').toUpperCase()).join('-');
}

// ---------- Decodificacao de cada tipo de frame ----------
function parseHandshake(frame) {
    const acct = readBcdPacked(frame.subarray(4, 6)).replace(/^0+/, '') || '0';
    const nic = formatMac(frame.subarray(6, 9));
    return { account: acct, nic };
}

function parseEventCompact(frame) {
    const acct = readBcdPacked(frame.subarray(4, 6)).replace(/^0+/, '') || '0';
    const payload = frame.subarray(6, 9);
    const mac = frame.subarray(9, 15);

    const b0 = payload[0];
    const b1 = payload[1];
    const q = (b0 >> 4) & 0x0f;
    const evtU = b0 & 0x0f;
    const evtT = (b1 >> 4) & 0x0f;
    const evtH = b1 & 0x0f;
    const evt = evtH * 100 + evtT * 10 + evtU;
    const qevt = q * 1000 + evt;
    const extraByte = payload[2];
    const description = describeEvent(qevt);
    return {
        account: acct,
        mac: formatMac(mac),
        payloadHex: payload.toString('hex'),
        extraHex: extraByte.toString(16).padStart(2, '0'),
        contactId: { q, evt, qevt, partition: '00', zone: '000', extra: extraByte, description },
    };
}

function parseEventCid(frame) {
    if (frame.length !== 20) {
        return { error: `tamanho inesperado para TYPE 0xC1: ${frame.length}` };
    }
    const acct = readDigits(frame, 4, 4).replace(/^0+/, '') || '0';
    const mt = readDigits(frame, 8, 2);
    const q = readDigits(frame, 10, 1);
    const evt = readDigits(frame, 11, 3);
    const gg = readDigits(frame, 14, 2);
    const zzz = readDigits(frame, 16, 3);
    const qevtNum = parseInt(q + evt, 10);
    const description = describeEvent(qevtNum);
    return {
        account: acct,
        mac: null,
        contactId: {
            mt,
            q: parseInt(q, 10),
            evt: parseInt(evt, 10),
            qevt: qevtNum,
            partition: gg,
            zone: zzz,
            description,
        },
    };
}

// ---------- Parser principal ----------
function parseFrame(frame) {
    if (frame.length < 4) return { ok: false, error: 'frame curto demais' };
    if (frame[0] !== STX) return { ok: false, error: 'STX invalido' };

    const len = frame[1];
    if (frame.length !== len + 1) {
        return { ok: false, error: `tamanho invalido: esperado ${len + 1}, recebido ${frame.length}` };
    }

    const type = frame[2];
    const chkRecv = frame[frame.length - 1];
    const chkCalc = crc8(frame.subarray(1, frame.length - 1));
    const chkOk = chkRecv === chkCalc;

    const out = {
        ok: chkOk,
        chkOk,
        chkRecv: chkRecv.toString(16).padStart(2, '0'),
        chkCalc: chkCalc.toString(16).padStart(2, '0'),
        type,
        typeName: type === TYPE_HANDSHAKE ? 'HANDSHAKE'
            : type === TYPE_EVENT_CID ? 'EVENTO_CID'
            : type === TYPE_EVENT_COMPACT ? 'EVENTO_COMPACTO'
            : `TIPO_0x${type.toString(16)}`,
    };

    if (type === TYPE_HANDSHAKE && frame.length === 10) {
        Object.assign(out, parseHandshake(frame));
    } else if (type === TYPE_EVENT_COMPACT && frame.length === 16) {
        Object.assign(out, parseEventCompact(frame));
    } else if (type === TYPE_EVENT_CID && frame.length === 20) {
        Object.assign(out, parseEventCid(frame));
    } else {
        out.unknownLayout = true;
        out.bodyHex = frame.subarray(3, frame.length - 1).toString('hex');
    }

    return out;
}

// ---------- ACK ----------
function buildAck(frame) {
    const type = frame[2];
    const ack = Buffer.from([STX, 0x04, type, ACK_FIXED_BYTE, 0x00]);
    ack[4] = crc8(ack.subarray(1, 4));
    return ack;
}

// ---------- Logging com rotacao por tamanho ----------
function ts() { return new Date().toISOString(); }

let rotating = false;

function logEvent(line) {
    try {
        fs.appendFileSync(LOG_FILE, `${ts()} ${line}\n`);
        rotateLogIfNeeded();
    } catch (e) {
        console.error(`[${ts()}] Erro ao gravar log: ${e.message}`);
    }
}

function rotateLogIfNeeded() {
    if (rotating) return;
    let size = 0;
    try {
        if (!fs.existsSync(LOG_FILE)) return;
        size = fs.statSync(LOG_FILE).size;
    } catch (e) {
        console.error(`[${ts()}] Erro ao verificar tamanho do log: ${e.message}`);
        return;
    }
    if (size < LOG_MAX_BYTES) return;

    rotating = true;
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const rotated = path.join(path.dirname(LOG_FILE), `eventos-${stamp}.log`);

    try {
        fs.renameSync(LOG_FILE, rotated);
        console.log(`[${ts()}] LOG atingiu ${size} bytes (limite ${LOG_MAX_BYTES}). Rotacionado para ${path.basename(rotated)}`);
    } catch (e) {
        console.error(`[${ts()}] Erro ao rotacionar log: ${e.message}`);
        rotating = false;
        return;
    }

    sendLogByEmail(rotated, size)
        .catch(err => console.error(`[${ts()}] Falha ao enviar log por email: ${err.message}`))
        .finally(() => {
            try {
                fs.unlinkSync(rotated);
                console.log(`[${ts()}] LOG rotacionado removido apos envio`);
            } catch (_) {}
            rotating = false;
        });
}

function sendLogByEmail(filepath, size) {
    return new Promise((resolve, reject) => {
        if (!MAIL_USER || !MAIL_PASS || !MAIL_LOG_TO) {
            console.warn(`[${ts()}] Envio do log por email desativado (faltam MAIL_USER/MAIL_PASS/MAIL_LOG_TO)`);
            return resolve();
        }
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: { user: MAIL_USER, pass: MAIL_PASS },
        });
        const filename = path.basename(filepath);
        transporter.sendMail({
            from: MAIL_FROM,
            to: MAIL_LOG_TO,
            subject: `[Central Monitoramento] Log rotacionado (${(size / 1024).toFixed(1)} KB)`,
            text: `O arquivo de log atingiu ${size} bytes (limite ${LOG_MAX_BYTES}).\n` +
                  `Anexo: ${filename}\n\n` +
                  `Apos o envio o arquivo sera removido do servidor e um novo eventos.log sera criado vazio.`,
            attachments: [{ filename, path: filepath }],
        }, (err, info) => {
            if (err) return reject(err);
            console.log(`[${ts()}] Email com log rotacionado enviado: ${info.response}`);
            resolve();
        });
    });
}

// ---------- Servidor TCP ----------
const tcpServer = net.createServer((socket) => {
    const clientAddr = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log(`\n[${ts()}] CONEXAO de ${clientAddr}`);

    let buf = Buffer.alloc(0);

    socket.on('data', (chunk) => {
        buf = Buffer.concat([buf, chunk]);

        while (true) {
            const stxIdx = buf.indexOf(STX);
            if (stxIdx === -1) {
                if (buf.length > 0) {
                    console.log(`  ! Descartando ${buf.length} byte(s) sem STX: ${buf.toString('hex')}`);
                }
                buf = Buffer.alloc(0);
                break;
            }
            if (stxIdx > 0) {
                console.log(`  ! Descartando ${stxIdx} byte(s) antes do STX: ${buf.subarray(0, stxIdx).toString('hex')}`);
                buf = buf.subarray(stxIdx);
            }
            if (buf.length < 2) break;
            const total = buf[1] + 1;
            if (buf.length < total) break;

            const frame = Buffer.from(buf.subarray(0, total));
            buf = buf.subarray(total);
            handleFrame(socket, clientAddr, frame);
        }
    });

    socket.on('end', () => console.log(`[${ts()}] FIM (FIN) de ${clientAddr}`));
    socket.on('close', (hadErr) => console.log(`[${ts()}] CLOSE de ${clientAddr}${hadErr ? ' (com erro)' : ''}`));
    socket.on('error', (err) => console.error(`[${ts()}] ERRO em ${clientAddr}: ${err.message}`));
});

function handleFrame(socket, clientAddr, frame) {
    const hex = frame.toString('hex');
    console.log(`\n  RX [${clientAddr}] ${hex}`);

    const parsed = parseFrame(frame);

    if (!parsed.chkOk) {
        console.log(`    ! CRC invalido (recv=0x${parsed.chkRecv} calc=0x${parsed.chkCalc})`);
    }
    console.log(`    Tipo: ${parsed.typeName}${parsed.account ? ` | Conta: ${parsed.account}` : ''}`);
    if (parsed.nic) console.log(`    NIC (3 bytes finais do MAC): ${parsed.nic}`);
    if (parsed.mac) console.log(`    MAC: ${parsed.mac}`);

    if (parsed.contactId) {
        const c = parsed.contactId;
        const d = c.description;
        const extra = c.extra !== undefined ? ` extra=0x${c.extra.toString(16).padStart(2, '0')}` : '';
        console.log(`    Q=${c.q} EVT=${c.evt} GG=${c.partition} ZZZ=${c.zone}${extra}`);
        console.log(`    => ${d.label} (Particao ${c.partition}, Zona ${c.zone})`);
        logEvent(`conta=${parsed.account} ${d.label} P=${c.partition} Z=${c.zone}${extra} (raw=${hex})`);

        if (!eventsToIgnore.includes(c.qevt)) {
            try {
                const priority = eventsToAlert.includes(c.qevt) ? 1 : 0;
                notifyApp(d.name, `Zona = ${c.zone}`, priority);
            } catch (error) {
                logEvent(`Error notifying app: ${error.message}`);
            }
        }
        if (eventsToAlertByMail.includes(c.qevt)) {
            try {
                sendEmail(d.name, `Zona = ${c.zone}`);
            } catch (error) {
                logEvent(`Error sending email: ${error.message}`);
            }
        }
    } else if (parsed.unknownLayout) {
        console.log(`    !! Layout desconhecido. body(hex)=${parsed.bodyHex}`);
        logEvent(`conta=${parsed.account || '?'} ${parsed.typeName} LAYOUT_DESCONHECIDO body=${parsed.bodyHex} (raw=${hex})`);
    } else {
        logEvent(`conta=${parsed.account || '?'} ${parsed.typeName} (raw=${hex})`);
    }

    const ack = buildAck(frame);
    socket.write(ack);
    console.log(`  TX [${clientAddr}] ${ack.toString('hex')} (ACK)`);
}

// ---------- Notificacoes ----------
function notifyApp(title, label, priority) {
    if (!PUSHOVER_TOKEN || !PUSHOVER_USER) {
        console.warn(`[${ts()}] Pushover desativado (faltam PUSHOVER_TOKEN/PUSHOVER_USER)`);
        return;
    }
    const message = encodeURIComponent(label);
    const t = encodeURIComponent(title);
    const options = {
        hostname: 'api.pushover.net',
        path: `/1/messages.json?token=${PUSHOVER_TOKEN}&user=${PUSHOVER_USER}&message=${message}&title=${t}&priority=${priority}`,
        method: 'POST',
    };
    const req = https.request(options, (res) => {
        res.on('data', (d) => console.log(d.toString()));
    });
    req.on('error', (err) => console.error(`[${ts()}] Erro Pushover: ${err.message}`));
    req.end();
}

function sendEmail(title, label) {
    if (!MAIL_USER || !MAIL_PASS || !MAIL_TO) {
        console.warn(`[${ts()}] Envio de email desativado (faltam MAIL_USER/MAIL_PASS/MAIL_TO)`);
        return;
    }
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: { user: MAIL_USER, pass: MAIL_PASS },
    });
    const mailOptions = {
        from: MAIL_FROM,
        to: MAIL_TO,
        subject: title,
        text: label,
    };
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) return console.log(`[${ts()}] Erro email: ${error.message}`);
        console.log(`[${ts()}] Email enviado: ${info.response}`);
    });
}

// ---------- HTTP Healthcheck (Render) ----------
const httpServer = http.createServer((req, res) => {
    if (req.url === '/log' && fs.existsSync(LOG_FILE)) {
        const stat = fs.statSync(LOG_FILE);
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(`# eventos.log (${stat.size} bytes / ${LOG_MAX_BYTES} max)\n\n` +
                fs.readFileSync(LOG_FILE, 'utf8'));
        return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({
        status: 'ok',
        service: 'central-monitoramento-v2',
        timestamp: ts(),
        tcp: { host: HOST, port: TCP_PORT },
        log: {
            file: LOG_FILE,
            maxBytes: LOG_MAX_BYTES,
            currentBytes: fs.existsSync(LOG_FILE) ? fs.statSync(LOG_FILE).size : 0,
        },
    }, null, 2));
});

// ---------- Boot ----------
tcpServer.listen(TCP_PORT, HOST, () => {
    console.log(`[${ts()}] Receptor Contact ID Vetti (TCP) rodando em ${HOST}:${TCP_PORT}`);
    console.log(`[${ts()}] Logs de eventos: ${LOG_FILE} (max ${LOG_MAX_BYTES} bytes)`);
});

httpServer.listen(PORT, HOST, () => {
    console.log('process.env', process.env);
    console.log(`[${ts()}] HTTP healthcheck em ${HOST}:${PORT}`);
});

// ---------- Self-test ao iniciar ----------
(function selfTest() {
    const tests = [
        { name: 'handshake', hex: '0209c040128122c943e8', expectChk: 0xe8, expectAck: '0204c080cf' },
        { name: 'evento compacto (teste periodico 1602)', hex: '020fc240128112064480342822c943c8', expectChk: 0xc8, expectAck: '0204c280e5', expectQevt: 1602 },
        { name: 'evento CID expandido - reset 1305', hex: '0213c14001020801010801030a050a0a0a0a04c7', expectChk: 0xc7, expectAck: '0204c180da', expectQevt: 1305 },
        { name: 'evento CID expandido - VettiConfig 1627', hex: '0213c140010208010108010602070a0a0a0a0a0a', expectChk: 0x0a, expectAck: '0204c180da', expectQevt: 1627 },
        { name: 'evento CID expandido - teste periodico 1602', hex: '0213c14001020801010801060a020a0a0a0a0a6d', expectChk: 0x6d, expectAck: '0204c180da', expectQevt: 1602 },
        { name: 'evento CID expandido - polling loop 1141', hex: '0213c140010208010108010104010a010a0a02fb', expectChk: 0xfb, expectAck: '0204c180da', expectQevt: 1141 },
        { name: 'evento CID expandido - arme 3401', hex: '0213c14001020801010803040a010a010a0a0846', expectChk: 0x46, expectAck: '0204c180da', expectQevt: 3401 },
        { name: 'evento CID expandido - desarme 1401', hex: '0213c14001020801010801040a010a010a0a08b4', expectChk: 0xb4, expectAck: '0204c180da', expectQevt: 1401 },
    ];

    let allOk = true;
    for (const t of tests) {
        const buf = Buffer.from(t.hex, 'hex');
        const calc = crc8(buf.subarray(1, buf.length - 1));
        const crcOk = calc === t.expectChk;
        if (!crcOk) allOk = false;

        const parsed = parseFrame(buf);
        const ack = buildAck(buf);
        const ackHex = ack.toString('hex');
        const ackOk = ackHex === t.expectAck;
        if (!ackOk) allOk = false;

        let qevtOk = true;
        if (t.expectQevt) {
            qevtOk = parsed.contactId && parsed.contactId.qevt === t.expectQevt;
            if (!qevtOk) allOk = false;
        }

        const status = (crcOk && ackOk && qevtOk) ? 'OK' : 'FALHA';
        console.log(`  self-test ${status} | ${t.name}`);
    }
    if (!allOk) {
        console.error('\nFALHA NO SELF-TEST. Abortando.');
        process.exit(1);
    }
    console.log('');
})();
