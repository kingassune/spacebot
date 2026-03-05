//! Unit tests for the James security platform modules.
//!
//! Covers red_team, blue_team, exploit_engine, and pentest modules.

// ============================================================================
// Red Team Tests
// ============================================================================

#[cfg(test)]
mod red_team_tests {
    use james::red_team::apt_emulation::{AptGroup, load_apt_profile};
    use james::red_team::exfiltration::{
        DataClassification, ExfilChannel, ExfilConfig, chunk_data,
    };
    use james::red_team::recon::{OutputFormat, ReconConfig, ReconPhase};

    #[test]
    fn test_red_team_recon_config_from_scope() {
        let config = ReconConfig::from_scope("example.com");
        assert_eq!(config.target, "example.com");
        assert!(config.passive_only);
        assert!(!config.scope.is_empty());
        assert!(
            config
                .allowed_techniques
                .contains(&ReconPhase::PassiveRecon)
        );
        assert_eq!(config.output_format, OutputFormat::Text);
    }

    #[test]
    fn test_red_team_recon_config_fields() {
        let config = ReconConfig {
            target: "192.168.1.0/24".to_string(),
            scope: vec!["192.168.1.0/24".to_string()],
            allowed_techniques: vec![ReconPhase::PassiveRecon, ReconPhase::ActiveRecon],
            output_format: OutputFormat::Json,
            passive_only: false,
        };
        assert!(!config.passive_only);
        assert_eq!(config.allowed_techniques.len(), 2);
        assert_eq!(config.output_format, OutputFormat::Json);
    }

    #[test]
    fn test_red_team_apt_profile_apt29() {
        let profile = load_apt_profile(&AptGroup::Apt29);
        assert!(!profile.name.is_empty(), "APT29 profile should have a name");
        assert!(
            !profile.ttps.is_empty(),
            "APT29 profile should include TTPs"
        );
        assert!(
            !profile.known_tools.is_empty(),
            "APT29 profile should list known tools"
        );
        assert!(
            !profile.objectives.is_empty(),
            "APT29 profile should have objectives"
        );
    }

    #[test]
    fn test_red_team_apt_profile_lazarus() {
        let profile = load_apt_profile(&AptGroup::Lazarus);
        assert!(!profile.name.is_empty());
        assert!(!profile.nation_state.is_empty());
        assert!(!profile.mitre_tactics.is_empty());
    }

    #[test]
    fn test_red_team_apt_profile_apt41() {
        let profile = load_apt_profile(&AptGroup::Apt41);
        assert!(!profile.name.is_empty());
        assert!(!profile.ttps.is_empty());
    }

    #[test]
    fn test_red_team_exfiltration_chunk_data_basic() {
        let data = b"Hello, World! This is test data for chunking.";
        let chunks = chunk_data(data, 10);
        assert!(!chunks.is_empty());
        // Verify all data is preserved
        let reassembled: Vec<u8> = chunks.into_iter().flatten().collect();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_red_team_exfiltration_chunk_data_exact_size() {
        let data = vec![0u8; 100];
        let chunks = chunk_data(&data, 25);
        assert_eq!(chunks.len(), 4);
        for chunk in &chunks {
            assert_eq!(chunk.len(), 25);
        }
    }

    #[test]
    fn test_red_team_exfiltration_chunk_data_smaller_than_chunk_size() {
        let data = b"small";
        let chunks = chunk_data(data, 100);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], data);
    }

    #[test]
    fn test_red_team_exfiltration_chunk_data_empty() {
        let chunks = chunk_data(&[], 10);
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_red_team_exfil_config_construction() {
        let config = ExfilConfig {
            target_host: "10.0.0.1".to_string(),
            channel: ExfilChannel::DnsTunneling,
            data_classification: DataClassification::Confidential,
            chunk_size_bytes: 512,
            encrypt: true,
        };
        assert_eq!(config.chunk_size_bytes, 512);
        assert!(config.encrypt);
        assert_eq!(config.channel, ExfilChannel::DnsTunneling);
    }
}

// ============================================================================
// Blue Team Tests
// ============================================================================

#[cfg(test)]
mod blue_team_tests {
    use james::blue_team::detection::{
        DetectionRule, Indicator, IndicatorType, RuleFormat, Severity, generate_yara_rule,
    };
    use james::blue_team::malware_analysis::{
        BehavioralIndicator, classify_by_indicators, compute_entropy,
    };
    use james::blue_team::siem_soar::{QueryBuilder, SiemPlatform};
    use james::blue_team::threat_intel::{
        Ioc, IocType, ThreatIntelReport, correlate_iocs, enrich_ioc, score_ioc,
    };

    #[test]
    fn test_blue_team_detection_rule_construction() {
        let rule = DetectionRule::new("test-rule", RuleFormat::Yara, "rule test {}".to_string());
        assert_eq!(rule.name, "test-rule");
        assert_eq!(rule.format, RuleFormat::Yara);
        assert!(!rule.id.is_empty(), "rule id should be auto-generated");
        assert_eq!(rule.severity, Severity::Medium);
    }

    #[test]
    fn test_blue_team_generate_yara_rule_for_ip() {
        let indicator = Indicator {
            value: "192.168.1.100".to_string(),
            indicator_type: IndicatorType::IpAddress,
        };
        let rule = generate_yara_rule(&indicator);
        assert!(
            rule.contains("rule "),
            "generated YARA rule should start with 'rule'"
        );
        assert!(
            rule.contains("192"),
            "rule should include the indicator value"
        );
    }

    #[test]
    fn test_blue_team_generate_yara_rule_for_domain() {
        let indicator = Indicator {
            value: "malicious.example.com".to_string(),
            indicator_type: IndicatorType::Domain,
        };
        let rule = generate_yara_rule(&indicator);
        assert!(rule.contains("rule "));
        assert!(rule.contains("malicious"));
    }

    #[test]
    fn test_blue_team_malware_entropy_uniform_bytes() {
        // A buffer of all zeros has zero entropy
        let all_zeros = vec![0u8; 256];
        let entropy = compute_entropy(&all_zeros);
        assert!(
            entropy < 0.001,
            "uniform buffer should have near-zero entropy, got {entropy}"
        );
    }

    #[test]
    fn test_blue_team_malware_entropy_random_bytes() {
        // A buffer with all 256 distinct byte values has maximum entropy (8.0)
        let max_entropy_data: Vec<u8> = (0..=255u8).collect();
        let entropy = compute_entropy(&max_entropy_data);
        assert!(
            entropy > 7.9,
            "buffer with all byte values should have high entropy (~8.0), got {entropy}"
        );
    }

    #[test]
    fn test_blue_team_malware_entropy_empty() {
        let entropy = compute_entropy(&[]);
        assert_eq!(entropy, 0.0, "empty buffer should have zero entropy");
    }

    #[test]
    fn test_blue_team_malware_classify_by_indicators_ransomware() {
        let indicators = vec![
            BehavioralIndicator {
                category: "file_system".to_string(),
                description: "Encrypts files with RSA key".to_string(),
                severity: "critical".to_string(),
                raw_event: "encrypt call detected".to_string(),
            },
            BehavioralIndicator {
                category: "network".to_string(),
                description: "Drops ransom note README.txt".to_string(),
                severity: "critical".to_string(),
                raw_event: "file write: README.txt".to_string(),
            },
        ];
        let classification = classify_by_indicators(&indicators);
        use james::blue_team::malware_analysis::MalwareClassification;
        assert_eq!(classification, MalwareClassification::Ransomware);
    }

    #[test]
    fn test_blue_team_threat_intel_ioc_creation() {
        let ioc = Ioc::new("10.0.0.1", IocType::IpAddress, "manual");
        assert_eq!(ioc.value, "10.0.0.1");
        assert_eq!(ioc.ioc_type, IocType::IpAddress);
        assert_eq!(ioc.source, "manual");
        assert_eq!(ioc.confidence, 50);
    }

    #[test]
    fn test_blue_team_threat_intel_score_ioc() {
        let ioc = Ioc::new("evil.example.com", IocType::Domain, "feed");
        let score = score_ioc(&ioc);
        assert_eq!(score, ioc.confidence);
    }

    #[test]
    fn test_blue_team_threat_intel_correlate_iocs_groups_by_type() {
        let iocs = vec![
            Ioc::new("1.2.3.4", IocType::IpAddress, "feed"),
            Ioc::new("5.6.7.8", IocType::IpAddress, "feed"),
            Ioc::new("evil.com", IocType::Domain, "feed"),
        ];
        let groups = correlate_iocs(&iocs);
        // Should produce two groups: one for IP addresses, one for domains
        assert_eq!(groups.len(), 2, "should group into 2 type buckets");
        let ip_group = groups.iter().find(|g| g[0].ioc_type == IocType::IpAddress);
        assert!(ip_group.is_some());
        assert_eq!(ip_group.unwrap().len(), 2);
    }

    #[test]
    fn test_blue_team_threat_intel_enrich_ioc_adds_tags() {
        let mut ioc = Ioc::new("evil.com", IocType::Domain, "feed");
        let mut report = ThreatIntelReport::new();
        report
            .iocs
            .push(Ioc::new("evil.com", IocType::Domain, "feed"));
        report.ttps.push("T1566".to_string());

        enrich_ioc(&mut ioc, &[report]);
        assert!(
            ioc.tags.contains(&"T1566".to_string()),
            "enrichment should add TTP tags from matching report"
        );
    }

    #[test]
    fn test_blue_team_siem_query_builder_kql() {
        let mut builder = QueryBuilder::new(SiemPlatform::Elastic);
        builder.add_filter("event.type", "process_start");
        builder.add_filter("process.name", "powershell.exe");
        let query = builder.build();
        assert!(
            query.contains("event.type"),
            "KQL query should include filter fields"
        );
        assert!(
            query.contains("AND"),
            "KQL query with multiple filters should use AND"
        );
    }

    #[test]
    fn test_blue_team_siem_query_builder_splunk() {
        let mut builder = QueryBuilder::new(SiemPlatform::Splunk);
        builder.add_filter("src_ip", "10.0.0.1");
        let query = builder.build();
        assert!(
            query.contains("search"),
            "SPL query should start with 'search'"
        );
        assert!(
            query.contains("src_ip"),
            "SPL query should include filter field"
        );
    }

    #[test]
    fn test_blue_team_siem_query_builder_empty_filters() {
        let builder = QueryBuilder::new(SiemPlatform::Elastic);
        let query = builder.build();
        // Should return an empty string or base query without errors
        assert!(
            query.is_empty(),
            "builder with no filters should produce empty query"
        );
    }
}

// ============================================================================
// Exploit Engine Tests
// ============================================================================

#[cfg(test)]
mod exploit_engine_tests {
    use james::exploit_engine::crash_analysis::{
        CrashInfo, CrashType, Exploitability, assess_exploitability, classify_crash,
        compute_stack_hash,
    };
    use james::exploit_engine::fuzzing::{CorpusEntry, CorpusManager};
    use james::exploit_engine::payload_gen::{Encoding, encode_payload};

    #[test]
    fn test_exploit_engine_classify_crash_heap_overflow() {
        let trace = vec!["heap-buffer-overflow in target_function".to_string()];
        assert_eq!(classify_crash(&trace), CrashType::HeapOverflow);
    }

    #[test]
    fn test_exploit_engine_classify_crash_use_after_free() {
        let trace = vec![
            "ERROR: AddressSanitizer: heap-use-after-free".to_string(),
            "  #0 0x... in vulnerable_func".to_string(),
        ];
        assert_eq!(classify_crash(&trace), CrashType::UseAfterFree);
    }

    #[test]
    fn test_exploit_engine_classify_crash_null_deref() {
        let trace = vec!["SIGSEGV: null pointer dereference".to_string()];
        assert_eq!(classify_crash(&trace), CrashType::NullDeref);
    }

    #[test]
    fn test_exploit_engine_classify_crash_stack_overflow() {
        let trace = vec!["stack-overflow detected in recursive_func".to_string()];
        assert_eq!(classify_crash(&trace), CrashType::StackOverflow);
    }

    #[test]
    fn test_exploit_engine_classify_crash_double_free() {
        let trace = vec!["ERROR: AddressSanitizer: double-free at 0xdeadbeef".to_string()];
        assert_eq!(classify_crash(&trace), CrashType::DoubleFree);
    }

    #[test]
    fn test_exploit_engine_assess_exploitability_heap_overflow() {
        let crash = CrashInfo {
            id: "crash-001".to_string(),
            crash_type: CrashType::HeapOverflow,
            stack_trace: vec!["heap-buffer-overflow".to_string()],
            register_state: std::collections::HashMap::new(),
            exploitability: Exploitability::Unknown,
            reproduction_cmd: "./target input.bin".to_string(),
            timestamp: chrono::Utc::now(),
        };
        assert_eq!(assess_exploitability(&crash), Exploitability::Exploitable);
    }

    #[test]
    fn test_exploit_engine_assess_exploitability_use_after_free() {
        let crash = CrashInfo {
            id: "crash-002".to_string(),
            crash_type: CrashType::UseAfterFree,
            stack_trace: vec![],
            register_state: std::collections::HashMap::new(),
            exploitability: Exploitability::Unknown,
            reproduction_cmd: String::new(),
            timestamp: chrono::Utc::now(),
        };
        assert_eq!(assess_exploitability(&crash), Exploitability::Exploitable);
    }

    #[test]
    fn test_exploit_engine_assess_exploitability_null_deref_not_exploitable() {
        let crash = CrashInfo {
            id: "crash-003".to_string(),
            crash_type: CrashType::NullDeref,
            stack_trace: vec![],
            register_state: std::collections::HashMap::new(),
            exploitability: Exploitability::Unknown,
            reproduction_cmd: String::new(),
            timestamp: chrono::Utc::now(),
        };
        assert_eq!(
            assess_exploitability(&crash),
            Exploitability::ProbablyNotExploitable
        );
    }

    #[test]
    fn test_exploit_engine_corpus_manager_minimize_removes_duplicates() {
        let mut manager = CorpusManager::new("/tmp/corpus".to_string());
        manager.add_entry(CorpusEntry {
            id: "entry-1".to_string(),
            data: vec![1, 2, 3],
            coverage_increase: true,
            crash_triggering: false,
        });
        manager.add_entry(CorpusEntry {
            id: "entry-2".to_string(),
            data: vec![1, 2, 3],
            coverage_increase: true,
            crash_triggering: false,
        });
        manager.add_entry(CorpusEntry {
            id: "entry-3".to_string(),
            data: vec![4, 5, 6],
            coverage_increase: false,
            crash_triggering: false,
        });

        let removed = manager.minimize();
        assert_eq!(removed, 1, "should remove one duplicate entry");
    }

    #[test]
    fn test_exploit_engine_corpus_manager_minimize_no_duplicates() {
        let mut manager = CorpusManager::new("/tmp/corpus".to_string());
        manager.add_entry(CorpusEntry {
            id: "entry-1".to_string(),
            data: vec![1, 2, 3],
            coverage_increase: true,
            crash_triggering: false,
        });
        manager.add_entry(CorpusEntry {
            id: "entry-2".to_string(),
            data: vec![4, 5, 6],
            coverage_increase: false,
            crash_triggering: false,
        });

        let removed = manager.minimize();
        assert_eq!(removed, 0, "should not remove unique entries");
    }

    #[test]
    fn test_exploit_engine_payload_xor_encode_roundtrip() {
        let payload = b"shellcode bytes here";
        let key = 0x42u8;
        let encoded = encode_payload(payload, &Encoding::Xor, key);
        let decoded = encode_payload(&encoded, &Encoding::Xor, key);
        assert_eq!(decoded, payload, "XOR encode/decode should be a roundtrip");
    }

    #[test]
    fn test_exploit_engine_payload_xor_encode_differs_from_original() {
        let payload = vec![0x90u8; 16]; // NOP sled
        let encoded = encode_payload(&payload, &Encoding::Xor, 0xAA);
        assert_ne!(encoded, payload, "XOR encoding should change the payload");
    }

    #[test]
    fn test_exploit_engine_payload_base64_encode() {
        let payload = b"test payload";
        let encoded = encode_payload(payload, &Encoding::Base64, 0);
        // Base64 output should be valid ASCII
        let encoded_str = String::from_utf8(encoded).expect("base64 output should be valid UTF-8");
        assert!(
            !encoded_str.is_empty(),
            "base64 encoded output should not be empty"
        );
        assert_ne!(
            encoded_str.as_bytes(),
            payload,
            "base64 encoding should change the bytes"
        );
    }

    #[test]
    fn test_exploit_engine_stack_hash_deterministic() {
        let trace = vec![
            "frame_a".to_string(),
            "frame_b".to_string(),
            "frame_c".to_string(),
        ];
        let hash1 = compute_stack_hash(&trace);
        let hash2 = compute_stack_hash(&trace);
        assert_eq!(hash1, hash2, "stack hash should be deterministic");
        assert!(!hash1.is_empty(), "stack hash should not be empty");
    }

    #[test]
    fn test_exploit_engine_stack_hash_differs_for_different_traces() {
        let trace_a = vec!["function_alpha".to_string()];
        let trace_b = vec!["function_beta_different".to_string()];
        let hash_a = compute_stack_hash(&trace_a);
        let hash_b = compute_stack_hash(&trace_b);
        assert_ne!(
            hash_a, hash_b,
            "different stack traces should produce different hashes"
        );
    }
}

// ============================================================================
// Pentest Tests
// ============================================================================

#[cfg(test)]
mod pentest_tests {
    use james::pentest::enumeration::fingerprint_service;
    use james::pentest::reporting::{
        AttackComplexity, AttackVector, CvssImpact, CvssScope, CvssVector, Finding,
        FindingSeverity, PrivilegesRequired, UserInteraction, calculate_cvss_score,
        generate_executive_summary,
    };
    use james::pentest::scoping::{
        Authorization, EngagementScope, ScopeType, create_scope, is_authorized, validate_target,
    };
    use james::pentest::web_security::{generate_sqli_payloads, generate_xss_payloads};

    // ------ Scoping ------

    #[test]
    fn test_pentest_scoping_validate_target_in_scope() {
        let scope = create_scope(
            "ACME Corp",
            vec!["example.com".to_string(), "10.0.0.1".to_string()],
            ScopeType::BlackBox,
        );
        assert!(
            validate_target("example.com", &scope),
            "in-scope target should be valid"
        );
    }

    #[test]
    fn test_pentest_scoping_validate_target_not_in_scope() {
        let scope = create_scope(
            "ACME Corp",
            vec!["example.com".to_string()],
            ScopeType::BlackBox,
        );
        assert!(
            !validate_target("other.com", &scope),
            "out-of-scope target should not be valid"
        );
    }

    #[test]
    fn test_pentest_scoping_validate_target_excluded() {
        let mut scope = create_scope(
            "ACME Corp",
            vec!["example.com".to_string()],
            ScopeType::BlackBox,
        );
        scope.out_of_scope_targets.push("example.com".to_string());
        assert!(
            !validate_target("example.com", &scope),
            "explicitly excluded target should not be authorized"
        );
    }

    #[test]
    fn test_pentest_scoping_is_authorized_valid_window() {
        let auth = Authorization {
            client_name: "ACME Corp".to_string(),
            authorized_by: "CISO".to_string(),
            signature_hash: "abc123".to_string(),
            valid_from: chrono::Utc::now() - chrono::Duration::hours(1),
            valid_until: chrono::Utc::now() + chrono::Duration::hours(23),
        };
        assert!(
            is_authorized(&auth, "example.com"),
            "authorization within valid window should return true"
        );
    }

    #[test]
    fn test_pentest_scoping_is_authorized_expired() {
        let auth = Authorization {
            client_name: "ACME Corp".to_string(),
            authorized_by: "CISO".to_string(),
            signature_hash: "abc123".to_string(),
            valid_from: chrono::Utc::now() - chrono::Duration::days(10),
            valid_until: chrono::Utc::now() - chrono::Duration::days(1),
        };
        assert!(
            !is_authorized(&auth, "example.com"),
            "expired authorization should return false"
        );
    }

    #[test]
    fn test_pentest_scope_construction() {
        let scope: EngagementScope = create_scope(
            "Test Client",
            vec!["test.example.com".to_string()],
            ScopeType::WhiteBox,
        );
        assert_eq!(scope.client_name, "Test Client");
        assert_eq!(scope.in_scope_targets.len(), 1);
        assert!(!scope.engagement_id.is_empty());
        assert_eq!(scope.scope_type, ScopeType::WhiteBox);
    }

    // ------ CVSS Scoring ------

    #[test]
    fn test_pentest_cvss_score_critical_network_no_auth() {
        // AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → CVSS 9.8
        let vector = CvssVector {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: CvssScope::Unchanged,
            confidentiality_impact: CvssImpact::High,
            integrity_impact: CvssImpact::High,
            availability_impact: CvssImpact::High,
        };
        let score = calculate_cvss_score(&vector);
        // Standard CVSS 9.8 (±0.05 tolerance for rounding)
        assert!(
            (score - 9.8).abs() < 0.1,
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H should score ~9.8, got {score}"
        );
    }

    #[test]
    fn test_pentest_cvss_score_low_local_high_complexity() {
        // AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N → low score
        let vector = CvssVector {
            attack_vector: AttackVector::Local,
            attack_complexity: AttackComplexity::High,
            privileges_required: PrivilegesRequired::High,
            user_interaction: UserInteraction::Required,
            scope: CvssScope::Unchanged,
            confidentiality_impact: CvssImpact::Low,
            integrity_impact: CvssImpact::None,
            availability_impact: CvssImpact::None,
        };
        let score = calculate_cvss_score(&vector);
        assert!(
            score < 4.0,
            "high complexity / high privileges / local attack should have low CVSS, got {score}"
        );
    }

    #[test]
    fn test_pentest_cvss_score_no_impact_is_zero() {
        let vector = CvssVector {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: CvssScope::Unchanged,
            confidentiality_impact: CvssImpact::None,
            integrity_impact: CvssImpact::None,
            availability_impact: CvssImpact::None,
        };
        let score = calculate_cvss_score(&vector);
        assert_eq!(score, 0.0, "zero impact metrics should yield score 0.0");
    }

    #[test]
    fn test_pentest_cvss_score_in_range() {
        let vector = CvssVector {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::Low,
            user_interaction: UserInteraction::None,
            scope: CvssScope::Changed,
            confidentiality_impact: CvssImpact::High,
            integrity_impact: CvssImpact::High,
            availability_impact: CvssImpact::High,
        };
        let score = calculate_cvss_score(&vector);
        assert!(
            (0.0..=10.0).contains(&score),
            "CVSS score must be between 0 and 10, got {score}"
        );
    }

    // ------ Reporting ------

    #[test]
    fn test_pentest_reporting_executive_summary_counts() {
        let findings = vec![
            Finding {
                id: "F-001".to_string(),
                title: "SQLi".to_string(),
                severity: FindingSeverity::Critical,
                cvss_vector: None,
                cvss_score: Some(9.8),
                description: "SQL injection".to_string(),
                affected_components: vec!["login".to_string()],
                remediation: "Use prepared statements".to_string(),
                references: vec![],
            },
            Finding {
                id: "F-002".to_string(),
                title: "XSS".to_string(),
                severity: FindingSeverity::High,
                cvss_vector: None,
                cvss_score: Some(7.5),
                description: "Cross-site scripting".to_string(),
                affected_components: vec!["search".to_string()],
                remediation: "Encode output".to_string(),
                references: vec![],
            },
        ];
        let summary = generate_executive_summary(&findings);
        assert!(
            summary.contains("2"),
            "summary should mention total finding count"
        );
        assert!(
            summary.contains("critical")
                || summary.contains("Critical")
                || summary.contains("1 critical"),
            "summary should mention critical findings"
        );
    }

    // ------ Enumeration ------

    #[test]
    fn test_pentest_enumeration_fingerprint_http_service() {
        let banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.51 (Ubuntu)\r\n";
        let result = fingerprint_service(banner);
        assert_eq!(
            result.service.to_uppercase(),
            "HTTP",
            "should identify HTTP service from banner"
        );
    }

    #[test]
    fn test_pentest_enumeration_fingerprint_ssh_service() {
        let banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3";
        let result = fingerprint_service(banner);
        assert_eq!(
            result.service.to_uppercase(),
            "SSH",
            "should identify SSH service from banner"
        );
    }

    #[test]
    fn test_pentest_enumeration_fingerprint_unknown_service() {
        let banner = "";
        let result = fingerprint_service(banner);
        assert_eq!(result.service, "unknown");
    }

    // ------ Web Security ------

    #[test]
    fn test_pentest_web_xss_payloads_non_empty() {
        let payloads = generate_xss_payloads();
        assert!(!payloads.is_empty(), "XSS payload list should not be empty");
        // Verify at least one payload contains a script tag
        let has_script = payloads.iter().any(|p| {
            p.to_lowercase().contains("<script")
                || p.contains("javascript:")
                || p.contains("onerror")
        });
        assert!(
            has_script,
            "XSS payloads should include at least one script-based payload"
        );
    }

    #[test]
    fn test_pentest_web_sqli_payloads_non_empty() {
        let payloads = generate_sqli_payloads();
        assert!(
            !payloads.is_empty(),
            "SQLi payload list should not be empty"
        );
        // Verify at least one payload contains a SQL keyword
        let has_sql = payloads.iter().any(|p| {
            let lower = p.to_lowercase();
            lower.contains("select")
                || lower.contains("union")
                || lower.contains("or 1=1")
                || lower.contains("--")
                || lower.contains("'")
        });
        assert!(has_sql, "SQLi payloads should include SQL keywords");
    }
}
