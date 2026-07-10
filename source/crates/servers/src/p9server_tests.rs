//! 9P Server Integration Tests
//!
//! Tests for the 9P server implementation.

#[cfg(test)]
mod tests {
    use crate::plan9_common::types::Qid;
    use crate::net::protocol::{P9Msg, P9Codec, Stat};
    use crate::servers::p9server::P9ServerImpl;

    #[test]
    fn test_server_creation() {
        let server = P9ServerImpl::new(65536);
        assert_eq!(server.supported_versions.len(), 4);
    }

    #[test]
    fn test_version_negotiation() {
        let mut server = P9ServerImpl::new(65536);
        
        let msg = P9Msg::TVersion {
            tag: 0,
            msize: 65536,
            version: "9P2000".to_string(),
        };
        
        let result = server.handle_message(msg);
        assert!(result.is_ok());
        
        match result.unwrap() {
            P9Msg::RVersion { tag, msize, version } => {
                assert_eq!(tag, 0);
                assert_eq!(msize, 65536);
                assert_eq!(version, "9P2000");
            }
            _ => panic!("Expected RVersion"),
        }
    }

    #[test]
    fn test_attach() {
        let mut server = P9ServerImpl::new(65536);
        
        // First, negotiate version
        let version_msg = P9Msg::TVersion {
            tag: 0,
            msize: 65536,
            version: "9P2000".to_string(),
        };
        server.handle_message(version_msg).unwrap();
        
        // Then attach
        let attach_msg = P9Msg::TAttach {
            tag: 1,
            fid: 100,
            afid: 0xffffffff,
            uname: "testuser".to_string(),
            aname: "".to_string(),
        };
        
        let result = server.handle_message(attach_msg);
        assert!(result.is_ok());
        
        match result.unwrap() {
            P9Msg::RAttach { tag, qid } => {
                assert_eq!(tag, 1);
                assert_eq!(qid.path, 0); // Root directory
            }
            _ => panic!("Expected RAttach"),
        }
    }

    #[test]
    fn test_walk() {
        let mut server = P9ServerImpl::new(65536);
        
        // Negotiate version
        server.handle_message(P9Msg::TVersion {
            tag: 0,
            msize: 65536,
            version: "9P2000".to_string(),
        }).unwrap();
        
        // Attach
        server.handle_message(P9Msg::TAttach {
            tag: 1,
            fid: 100,
            afid: 0xffffffff,
            uname: "testuser".to_string(),
            aname: "".to_string(),
        }).unwrap();
        
        // Walk
        let walk_msg = P9Msg::TWalk {
            tag: 2,
            fid: 100,
            new_fid: 101,
            names: vec!["test".to_string()],
        };
        
        // This will return empty qids since test directory doesn't exist
        let result = server.handle_message(walk_msg);
        assert!(result.is_ok());
    }

    #[test]
    fn test_open() {
        let mut server = P9ServerImpl::new(65536);
        
        // Negotiate version
        server.handle_message(P9Msg::TVersion {
            tag: 0,
            msize: 65536,
            version: "9P2000".to_string(),
        }).unwrap();
        
        // Attach
        server.handle_message(P9Msg::TAttach {
            tag: 1,
            fid: 100,
            afid: 0xffffffff,
            uname: "testuser".to_string(),
            aname: "".to_string(),
        }).unwrap();
        
        // Open root directory
        let open_msg = P9Msg::TOpen {
            tag: 2,
            fid: 100,
            mode: 0, // OREAD
        };
        
        let result = server.handle_message(open_msg);
        assert!(result.is_ok());
    }

    #[test]
    fn test_clunk() {
        let mut server = P9ServerImpl::new(65536);
        
        // Negotiate version
        server.handle_message(P9Msg::TVersion {
            tag: 0,
            msize: 65536,
            version: "9P2000".to_string(),
        }).unwrap();
        
        // Attach
        server.handle_message(P9Msg::TAttach {
            tag: 1,
            fid: 100,
            afid: 0xffffffff,
            uname: "testuser".to_string(),
            aname: "".to_string(),
        }).unwrap();
        
        // Clunk
        let clunk_msg = P9Msg::TClunk {
            tag: 3,
            fid: 100,
        };
        
        let result = server.handle_message(clunk_msg);
        assert!(result.is_ok());
        
        match result.unwrap() {
            P9Msg::RClunk { tag } => {
                assert_eq!(tag, 3);
            }
            _ => panic!("Expected RClunk"),
        }
    }

    #[test]
    fn test_flush() {
        let mut server = P9ServerImpl::new(65536);
        
        // Negotiate version
        server.handle_message(P9Msg::TVersion {
            tag: 0,
            msize: 65536,
            version: "9P2000".to_string(),
        }).unwrap();
        
        // Flush non-existent tag
        let flush_msg = P9Msg::TFlush {
            tag: 5,
            oldtag: 999,
        };
        
        let result = server.handle_message(flush_msg);
        assert!(result.is_ok());
    }

    #[test]
    fn test_stat() {
        let mut server = P9ServerImpl::new(65536);
        
        // Negotiate version
        server.handle_message(P9Msg::TVersion {
            tag: 0,
            msize: 65536,
            version: "9P2000".to_string(),
        }).unwrap();
        
        // Attach
        server.handle_message(P9Msg::TAttach {
            tag: 1,
            fid: 100,
            afid: 0xffffffff,
            uname: "testuser".to_string(),
            aname: "".to_string(),
        }).unwrap();
        
        // Stat
        let stat_msg = P9Msg::TStat {
            tag: 4,
            fid: 100,
        };
        
        let result = server.handle_message(stat_msg);
        assert!(result.is_ok());
    }

    #[test]
    fn test_full_session() {
        let mut server = P9ServerImpl::new(65536);
        
        // 1. Version negotiation
        let version_result = server.handle_message(P9Msg::TVersion {
            tag: 0,
            msize: 65536,
            version: "9P2000".to_string(),
        });
        assert!(version_result.is_ok());
        
        // 2. Attach
        let attach_result = server.handle_message(P9Msg::TAttach {
            tag: 1,
            fid: 100,
            afid: 0xffffffff,
            uname: "testuser".to_string(),
            aname: "".to_string(),
        });
        assert!(attach_result.is_ok());
        
        // 3. Open directory
        let open_result = server.handle_message(P9Msg::TOpen {
            tag: 2,
            fid: 100,
            mode: 0,
        });
        assert!(open_result.is_ok());
        
        // 4. Read directory (if it had contents)
        let read_result = server.handle_message(P9Msg::TRead {
            tag: 3,
            fid: 100,
            offset: 0,
            count: 1024,
        });
        assert!(read_result.is_ok());
        
        // 5. Close
        let clunk_result = server.handle_message(P9Msg::TClunk {
            tag: 4,
            fid: 100,
        });
        assert!(clunk_result.is_ok());
    }

    #[test]
    fn test_9p2000u_auth() {
        let mut server = P9ServerImpl::new(65536);
        
        // Negotiate 9P2000.u
        let version_result = server.handle_message(P9Msg::TVersion {
            tag: 0,
            msize: 65536,
            version: "9P2000.u".to_string(),
        });
        assert!(version_result.is_ok());
        
        // Auth request
        let auth_result = server.handle_message(P9Msg::TAuth {
            tag: 1,
            afid: 50,
            uname: "testuser".to_string(),
            aname: "".to_string(),
        });
        assert!(auth_result.is_ok());
    }

    #[test]
    fn test_9p2000l_dotl() {
        let mut server = P9ServerImpl::new(65536);
        
        // Negotiate 9P2000.L
        let version_result = server.handle_message(P9Msg::TVersion {
            tag: 0,
            msize: 65536,
            version: "9P2000.L".to_string(),
        });
        assert!(version_result.is_ok());
        
        // Attach
        server.handle_message(P9Msg::TAttach {
            tag: 1,
            fid: 100,
            afid: 0xffffffff,
            uname: "testuser".to_string(),
            aname: "".to_string(),
        }).unwrap();
        
        // OpenAt (dotl)
        let openat_result = server.handle_message(P9Msg::TOpenAt {
            tag: 2,
            dfid: 100,
            flags: 0,
            mode: 0,
        });
        assert!(openat_result.is_ok());
    }

    #[test]
    fn test_9p2000e_locking() {
        let mut server = P9ServerImpl::new(65536);
        
        // Negotiate 9P2000.e
        let version_result = server.handle_message(P9Msg::TVersion {
            tag: 0,
            msize: 65536,
            version: "9P2000.e".to_string(),
        });
        assert!(version_result.is_ok());
        
        // Attach
        server.handle_message(P9Msg::TAttach {
            tag: 1,
            fid: 100,
            afid: 0xffffffff,
            uname: "testuser".to_string(),
            aname: "".to_string(),
        }).unwrap();
        
        // Open file first
        server.handle_message(P9Msg::TOpen {
            tag: 2,
            fid: 100,
            mode: 2, // ORDWR
        }).unwrap();
        
        // Try to acquire lock
        let lock_result = server.handle_message(P9Msg::TLock {
            tag: 3,
            fid: 100,
            lock_type: 1, // LOCK_EX
            flags: 0,
            start: 0,
            length: 0,
            proc_id: "test".to_string(),
        });
        assert!(lock_result.is_ok());
        
        // Release lock
        let unlock_result = server.handle_message(P9Msg::TLock {
            tag: 4,
            fid: 100,
            lock_type: 0, // LOCK_UN
            flags: 0,
            start: 0,
            length: 0,
            proc_id: "test".to_string(),
        });
        assert!(unlock_result.is_ok());
    }

    // ============================================================
    // 9P2000.e locking behaviour: conflict detection
    // ============================================================

    #[test]
    fn test_9p2000e_write_write_conflict() {
        let mut server = P9ServerImpl::new(65536);

        server.handle_message(P9Msg::TVersion {
            tag: 0, msize: 65536, version: "9P2000.e".to_string(),
        }).unwrap();
        server.handle_message(P9Msg::TAttach {
            tag: 1, fid: 100, afid: 0xffffffff,
            uname: "test".to_string(), aname: "".to_string(),
        }).unwrap();
        server.handle_message(P9Msg::TOpen {
            tag: 2, fid: 100, mode: 2,
        }).unwrap();

        // First writer wins (status 0).
        let r1 = server.handle_message(P9Msg::TLock {
            tag: 3, fid: 100, lock_type: 2, flags: 0,
            start: 0, length: 100, proc_id: "w1".to_string(),
        }).unwrap();
        match r1 {
            P9Msg::RLock { status, .. } => assert_eq!(status, 0),
            _ => panic!("expected RLock"),
        }

        // Second writer on the same range must fail (status 1).
        let r2 = server.handle_message(P9Msg::TLock {
            tag: 4, fid: 100, lock_type: 2, flags: 0,
            start: 50, length: 100, proc_id: "w2".to_string(),
        }).unwrap();
        match r2 {
            P9Msg::RLock { status, .. } => assert_eq!(status, 1),
            _ => panic!("expected RLock"),
        }
    }

    #[test]
    fn test_9p2000e_getlock_returns_held_lock() {
        let mut server = P9ServerImpl::new(65536);

        server.handle_message(P9Msg::TVersion {
            tag: 0, msize: 65536, version: "9P2000.e".to_string(),
        }).unwrap();
        server.handle_message(P9Msg::TAttach {
            tag: 1, fid: 100, afid: 0xffffffff,
            uname: "test".to_string(), aname: "".to_string(),
        }).unwrap();
        server.handle_message(P9Msg::TOpen {
            tag: 2, fid: 100, mode: 2,
        }).unwrap();

        // Acquire a write lock on a known range.
        server.handle_message(P9Msg::TLock {
            tag: 3, fid: 100, lock_type: 2, flags: 0,
            start: 10, length: 100, proc_id: "owner".to_string(),
        }).unwrap();

        // Probe with TGetLock on the same range — should report the lock.
        let probe = server.handle_message(P9Msg::TGetLock {
            tag: 4, fid: 100, lock_type: 2,
            start: 50, length: 10, proc_id: "?".to_string(),
        }).unwrap();
        match probe {
            P9Msg::RGetLock { lock_type, start, length, proc_id, .. } => {
                assert_eq!(lock_type, 2);
                assert_eq!(start, 10);
                assert_eq!(length, 100);
                assert_eq!(proc_id, b"owner".to_vec());
            }
            _ => panic!("expected RGetLock"),
        }
    }

    #[test]
    fn test_create_qid_uniqueness() {
        let mut server = P9ServerImpl::new(65536);

        server.handle_message(P9Msg::TVersion {
            tag: 0, msize: 65536, version: "9P2000".to_string(),
        }).unwrap();
        server.handle_message(P9Msg::TAttach {
            tag: 1, fid: 100, afid: 0xffffffff,
            uname: "test".to_string(), aname: "".to_string(),
        }).unwrap();

        // Create multiple files and verify QID paths are unique.
        let mut paths: Vec<u64> = Vec::new();
        for i in 0..10 {
            let r = server.handle_message(P9Msg::TCreate {
                tag: (10 + i) as u16,
                fid: 100,
                name: format!("file{}", i),
                mode: 0,
                perm: 0o644,
            }).unwrap();
            if let P9Msg::RCreate { qid, .. } = r {
                paths.push(qid.path);
            } else {
                panic!("expected RCreate");
            }
        }
        // Dedup should not change length (all paths are unique).
        let mut sorted = paths.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), paths.len(), "QID paths must be unique");
    }

    #[test]
    fn test_protocol_version_9p2000_e_round_trip() {
        use crate::servers::p9session::ProtocolVersion;
        assert_eq!(ProtocolVersion::from_str("9P2000.e"), ProtocolVersion::V9P2000E);
        assert_eq!(ProtocolVersion::V9P2000E.as_str(), "9P2000.e");
        // Lowercase should also resolve through the .u case alias.
        assert_eq!(ProtocolVersion::from_str("9P2000.u"), ProtocolVersion::V9P2000U);
    }
}
