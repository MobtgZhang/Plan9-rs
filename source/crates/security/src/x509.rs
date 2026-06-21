//! X.509 Certificate Parsing
//!
//! Implements X.509 certificate decoding and basic validation.

use alloc::string::String;
use alloc::vec::Vec;
use crate::asn1::{Asn1Element, Asn1Value};
use crate::bigint::BigInt;
use crate::SecurityError;

/// X.509 Certificate
#[derive(Debug, Clone)]
pub struct X509Certificate {
    /// Serial number
    pub serial: BigInt,
    /// Issuer distinguished name
    pub issuer: String,
    /// Subject distinguished name
    pub subject: String,
    /// Not before (UTC time string)
    pub not_before: String,
    /// Not after (UTC time string)
    pub not_after: String,
    /// Public key algorithm OID
    pub public_key_algorithm: Vec<u32>,
    /// Public key data
    pub public_key: Vec<u8>,
    /// Signature algorithm OID
    pub signature_algorithm: Vec<u32>,
    /// Signature bytes
    pub signature: Vec<u8>,
}

/// Parse X.509 certificate from DER
pub fn decode_x509_certificate(der: &[u8]) -> Result<X509Certificate, SecurityError> {
    // Parse outer sequence (Certificate)
    let (outer, _) = Asn1Element::decode_ber(der)?;
    
    // Get TBSCertificate sequence
    let sequence = match outer.value {
        Asn1Value::Sequence(elements) => elements,
        _ => return Err(SecurityError::InvalidInputLength),
    };
    
    if sequence.is_empty() {
        return Err(SecurityError::InvalidInputLength);
    }
    
    let tbs = &sequence[0];
    let tbs_elements = match &tbs.value {
        Asn1Value::Sequence(elems) => elems,
        _ => return Err(SecurityError::InvalidInputLength),
    };
    
    // Version (optional, context tag 0)
    let version_offset = if tbs_elements[0].tag == 0 {
        1
    } else {
        0
    };
    
    // SerialNumber (integer)
    let serial = match &tbs_elements[version_offset].value {
        Asn1Value::Integer(n) => n.clone(),
        _ => return Err(SecurityError::InvalidInputLength),
    };
    
    // Signature algorithm
    let sig_alg_offset = version_offset + 1;
    let sig_alg_oid = X509Certificate::extract_oid(&tbs_elements[sig_alg_offset])?;
    
    // Issuer
    let issuer_offset = version_offset + 2;
    let issuer = X509Certificate::extract_name(&tbs_elements[issuer_offset])?;
    
    // Validity
    let validity_offset = version_offset + 3;
    let (not_before, not_after) = X509Certificate::extract_validity(&tbs_elements[validity_offset])?;
    
    // Subject
    let subject_offset = version_offset + 4;
    let subject = X509Certificate::extract_name(&tbs_elements[subject_offset])?;
    
    // SubjectPublicKeyInfo
    let pubkey_offset = version_offset + 5;
    let (pubkey_alg_oid, pubkey) = X509Certificate::extract_public_key(&tbs_elements[pubkey_offset])?;
    
    // Find signature algorithm in outer sequence
    let sig_alg_oid = if sequence.len() > 1 {
        X509Certificate::extract_oid(&sequence[1])?
    } else {
        sig_alg_oid.clone()
    };
    
    // Find signature in outer sequence
    let signature = if sequence.len() > 2 {
        X509Certificate::extract_signature(&sequence[2])?
    } else {
        alloc::vec![]
    };
    
    Ok(X509Certificate {
        serial,
        issuer,
        subject,
        not_before,
        not_after,
        public_key_algorithm: pubkey_alg_oid,
        public_key: pubkey,
        signature_algorithm: sig_alg_oid,
        signature,
    })
}

impl X509Certificate {
    fn extract_oid(elem: &Asn1Element) -> Result<Vec<u32>, SecurityError> {
        match &elem.value {
            Asn1Value::Sequence(elements) => {
                if let Asn1Value::Oid(oid) = &elements[0].value {
                    Ok(oid.clone())
                } else {
                    Err(SecurityError::InvalidInputLength)
                }
            }
            Asn1Value::Oid(oid) => Ok(oid.clone()),
            _ => Err(SecurityError::InvalidInputLength),
        }
    }
    
    fn extract_name(elem: &Asn1Element) -> Result<String, SecurityError> {
        // Name is a sequence of RelativeDistinguishedName sets
        let mut parts = Vec::new();
        
        if let Asn1Value::Sequence(seq) = &elem.value {
            for set in seq {
                if let Asn1Value::Set(attr_set) = &set.value {
                    for attr in attr_set {
                        if let Asn1Value::Sequence(attr_seq) = &attr.value {
                            if attr_seq.len() >= 2 {
                                let oid = if let Asn1Value::Oid(o) = &attr_seq[0].value {
                                    o.clone()
                                } else {
                                    continue;
                                };
                                let value = if let Asn1Value::PrintableString(s) = &attr_seq[1].value {
                                    s.clone()
                                } else if let Asn1Value::Utf8String(s) = &attr_seq[1].value {
                                    s.clone()
                                } else {
                                    continue;
                                };
                                
                                let name = match oid.as_slice() {
                                    [2, 5, 4, 3] => "CN",
                                    [2, 5, 4, 6] => "C",
                                    [2, 5, 4, 7] => "L",
                                    [2, 5, 4, 8] => "ST",
                                    [2, 5, 4, 10] => "O",
                                    [2, 5, 4, 11] => "OU",
                                    _ => "?",
                                };
                                parts.push({
                                    let mut s = alloc::string::String::from(name);
                                    s.push('=');
                                    s.push_str(&value);
                                    s
                                });
                            }
                        }
                    }
                }
            }
        }
        
        Ok(parts.join(", "))
    }
    
    fn extract_validity(elem: &Asn1Element) -> Result<(String, String), SecurityError> {
        match &elem.value {
            Asn1Value::Sequence(elements) => {
                if elements.len() >= 2 {
                    let not_before = match &elements[0].value {
                        Asn1Value::UtcTime(s) => s.clone(),
                        _ => return Err(SecurityError::InvalidInputLength),
                    };
                    let not_after = match &elements[1].value {
                        Asn1Value::UtcTime(s) => s.clone(),
                        _ => return Err(SecurityError::InvalidInputLength),
                    };
                    Ok((not_before, not_after))
                } else {
                    Err(SecurityError::InvalidInputLength)
                }
            }
            _ => Err(SecurityError::InvalidInputLength),
        }
    }
    
    fn extract_public_key(elem: &Asn1Element) -> Result<(Vec<u32>, Vec<u8>), SecurityError> {
        match &elem.value {
            Asn1Value::Sequence(elements) => {
                // Algorithm identifier
                let alg_oid = Self::extract_oid(&elements[0])?;
                
                // SubjectPublicKey - bit string
                let pubkey = if let Asn1Value::BitString(data) = &elements[1].value {
                    data.clone()
                } else {
                    alloc::vec![]
                };
                
                Ok((alg_oid, pubkey))
            }
            _ => Err(SecurityError::InvalidInputLength),
        }
    }
    
    fn extract_signature(elem: &Asn1Element) -> Result<Vec<u8>, SecurityError> {
        match &elem.value {
            Asn1Value::BitString(data) => Ok(data.clone()),
            _ => Err(SecurityError::InvalidInputLength),
        }
    }
}
