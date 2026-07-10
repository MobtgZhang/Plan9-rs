pub const TICKETLEN: usize = 128;
pub const TICKREQLEN: usize = 128;
pub const AUTHENTLEN: usize = 48;
pub const CHALLEN: usize = 8;

pub const fn authlen() -> usize {
    AUTHENTLEN
}

pub fn conv_t2m(ticket: &Ticket) -> [u8; TICKETLEN] {
    let mut buf = [0u8; TICKETLEN];
    let mut p = 0;

    buf[p..p + CHALLEN].copy_from_slice(&ticket.chal);
    p += CHALLEN;

    buf[p] = ticket.num;
    p += 1;

    buf[p..p + 4].copy_from_slice(&ticket.id);
    p += 4;

    buf[p..p + AUTHENTLEN].copy_from_slice(&ticket.auth);
    // p now equals CHALLEN + 1 + 4 + AUTHENTLEN = TICKETLEN; no more writes.

    buf
}

pub fn conv_m2t(buf: &[u8]) -> Option<Ticket> {
    if buf.len() < CHALLEN + 1 + 4 + AUTHENTLEN {
        return None;
    }

    let mut p = 0;

    let mut chal = [0u8; CHALLEN];
    chal.copy_from_slice(&buf[p..p + CHALLEN]);
    p += CHALLEN;

    let num = buf[p];
    p += 1;

    let mut id = [0u8; 4];
    id.copy_from_slice(&buf[p..p + 4]);
    p += 4;

    let mut auth = [0u8; AUTHENTLEN];
    auth.copy_from_slice(&buf[p..p + AUTHENTLEN]);

    Some(Ticket { chal, num, id, auth })
}

pub fn conv_tr2m(ticketreq: &Ticketreq) -> [u8; TICKREQLEN] {
    let mut buf = [0u8; TICKREQLEN];
    let mut p = 0;

    // authdom: 2-byte length prefix + string
    let authdom_bytes = ticketreq.authdom.as_bytes();
    let authdom_len = authdom_bytes.len().min(u16::MAX as usize) as u16;
    buf[p..p + 2].copy_from_slice(&authdom_len.to_le_bytes());
    p += 2;
    let copy_len = authdom_bytes.len().min((TICKREQLEN - p).min(u16::MAX as usize));
    buf[p..p + copy_len].copy_from_slice(&authdom_bytes[..copy_len]);
    p += copy_len;

    // authid: 2-byte length prefix + string
    let authid_bytes = ticketreq.authid.as_bytes();
    let authid_len = authid_bytes.len().min(u16::MAX as usize) as u16;
    buf[p..p + 2].copy_from_slice(&authid_len.to_le_bytes());
    p += 2;
    let copy_len = authid_bytes.len().min((TICKREQLEN - p).min(u16::MAX as usize));
    buf[p..p + copy_len].copy_from_slice(&authid_bytes[..copy_len]);
    p += copy_len;

    // chal
    buf[p..p + CHALLEN].copy_from_slice(&ticketreq.chal);
    p += CHALLEN;

    // hostid: 2-byte length prefix + string
    let hostid_bytes = ticketreq.hostid.as_bytes();
    let hostid_len = hostid_bytes.len().min(u16::MAX as usize) as u16;
    buf[p..p + 2].copy_from_slice(&hostid_len.to_le_bytes());
    p += 2;
    let copy_len = hostid_bytes.len().min((TICKREQLEN - p).min(u16::MAX as usize));
    buf[p..p + copy_len].copy_from_slice(&hostid_bytes[..copy_len]);
    p += copy_len;

    // uid (little-endian)
    buf[p..p + 4].copy_from_slice(&ticketreq.uid.to_le_bytes());
    p += 4;

    // unused byte
    buf[p] = ticketreq._unused;
    // p now equals the end of the buffer; no more writes.

    buf
}

pub fn conv_m2tr(buf: &[u8]) -> Option<Ticketreq> {
    let mut p = 0;

    // authdom
    if p + 2 > buf.len() {
        return None;
    }
    let authdom_len = u16::from_le_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2;
    if p + authdom_len > buf.len() {
        return None;
    }
    let authdom = String::from_utf8_lossy(&buf[p..p + authdom_len]).to_string();
    p += authdom_len;

    // authid
    if p + 2 > buf.len() {
        return None;
    }
    let authid_len = u16::from_le_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2;
    if p + authid_len > buf.len() {
        return None;
    }
    let authid = String::from_utf8_lossy(&buf[p..p + authid_len]).to_string();
    p += authid_len;

    // chal
    if p + CHALLEN > buf.len() {
        return None;
    }
    let mut chal = [0u8; CHALLEN];
    chal.copy_from_slice(&buf[p..p + CHALLEN]);
    p += CHALLEN;

    // hostid
    if p + 2 > buf.len() {
        return None;
    }
    let hostid_len = u16::from_le_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2;
    if p + hostid_len > buf.len() {
        return None;
    }
    let hostid = String::from_utf8_lossy(&buf[p..p + hostid_len]).to_string();
    p += hostid_len;

    // uid
    if p + 4 > buf.len() {
        return None;
    }
    let uid = u32::from_le_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]]);
    p += 4;

    // unused
    let _unused = if p < buf.len() { buf[p] } else { 0 };

    Some(Ticketreq {
        authid,
        authdom,
        chal,
        hostid,
        uid,
        _unused,
    })
}

pub struct Ticket {
    pub chal: [u8; CHALLEN],
    pub num: u8,
    pub id: [u8; 4],
    pub auth: [u8; AUTHENTLEN],
}

pub struct Ticketreq {
    pub authid: String,
    pub authdom: String,
    pub chal: [u8; CHALLEN],
    pub hostid: String,
    pub uid: u32,
    pub _unused: u8,
}
