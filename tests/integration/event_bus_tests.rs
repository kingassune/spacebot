//! Integration tests for cross-module event bus propagation.

#[cfg(test)]
mod event_bus_tests {
    use james::event_bus::{
        BlockchainAlert, DetectionAlert, EventType, ExploitBlueprint, Finding, SecurityEvent,
        SecurityEventBus, ThreatIndicator, wire_blockchain_to_meta, wire_exploit_to_pentest,
        wire_vuln_to_blue_team,
    };

    #[test]
    fn event_bus_new_has_all_channels() {
        let bus = SecurityEventBus::new();
        // Verify we can subscribe to all known event types without panicking.
        assert!(bus.subscribe(&EventType::VulnDiscovered).is_some());
        assert!(bus.subscribe(&EventType::ExploitGenerated).is_some());
        assert!(bus.subscribe(&EventType::DetectionTriggered).is_some());
        assert!(bus.subscribe(&EventType::BlockchainAnomaly).is_some());
    }

    #[test]
    fn event_bus_publish_and_receive() {
        let bus = SecurityEventBus::new();
        let mut receiver = bus
            .subscribe(&EventType::VulnDiscovered)
            .expect("channel should exist");

        let finding = Finding {
            id: "JAMES-001".to_string(),
            title: "SQL Injection in login endpoint".to_string(),
            severity: "High".to_string(),
            description: "Unsanitised input passed directly to database query.".to_string(),
            source_module: "pentest".to_string(),
            affected_target: "https://example.com/login".to_string(),
        };

        let count = bus
            .publish(SecurityEvent::VulnDiscovered(finding.clone()))
            .expect("publish should succeed");

        assert_eq!(count, 1, "one subscriber should have received the event");

        let received = receiver.try_recv().expect("should have received event");
        if let SecurityEvent::VulnDiscovered(f) = received {
            assert_eq!(f.title, finding.title);
            assert_eq!(f.severity, "High");
        } else {
            panic!("wrong event type received");
        }
    }

    #[test]
    fn wire_vuln_notifies_blue_team() {
        let bus = SecurityEventBus::new();
        let mut receiver = bus
            .subscribe(&EventType::VulnDiscovered)
            .expect("channel should exist");

        let finding = Finding {
            id: "JAMES-002".to_string(),
            title: "Buffer overflow in custom parser".to_string(),
            severity: "Critical".to_string(),
            description: "Stack-based buffer overflow via crafted network packet.".to_string(),
            source_module: "red_team".to_string(),
            affected_target: "network-service:8080".to_string(),
        };

        wire_vuln_to_blue_team(&bus, finding).expect("wire should succeed");

        assert!(
            receiver.try_recv().is_ok(),
            "blue team should have been notified"
        );
    }

    #[test]
    fn wire_blockchain_to_meta_generates_two_events() {
        let bus = SecurityEventBus::new();
        let mut anomaly_rx = bus
            .subscribe(&EventType::BlockchainAnomaly)
            .expect("channel should exist");
        let mut extension_rx = bus
            .subscribe(&EventType::ExtensionProposed)
            .expect("channel should exist");

        let alert = BlockchainAlert {
            target: "0xdeadbeef".to_string(),
            anomaly_type: "reentrancy".to_string(),
            description: "Reentrancy in withdraw()".to_string(),
            estimated_impact_usd: Some(1_000_000),
        };

        wire_blockchain_to_meta(&bus, alert).expect("wire should succeed");

        assert!(anomaly_rx.try_recv().is_ok(), "anomaly event should be published");
        assert!(extension_rx.try_recv().is_ok(), "extension proposal should be published");
    }
}
