//! Digital forensics case management and evidence chain-of-custody for blue team operations.

use chrono::Utc;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub enum EvidenceType {
    MemoryDump,
    DiskImage,
    NetworkCapture,
    LogFile,
    RegistryHive,
    BrowserArtifact,
}

impl std::fmt::Display for EvidenceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            EvidenceType::MemoryDump => "Memory Dump",
            EvidenceType::DiskImage => "Disk Image",
            EvidenceType::NetworkCapture => "Network Capture",
            EvidenceType::LogFile => "Log File",
            EvidenceType::RegistryHive => "Registry Hive",
            EvidenceType::BrowserArtifact => "Browser Artifact",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ArtifactCategory {
    FileSystem,
    Registry,
    Network,
    Memory,
    Process,
    UserActivity,
}

impl std::fmt::Display for ArtifactCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ArtifactCategory::FileSystem => "File System",
            ArtifactCategory::Registry => "Registry",
            ArtifactCategory::Network => "Network",
            ArtifactCategory::Memory => "Memory",
            ArtifactCategory::Process => "Process",
            ArtifactCategory::UserActivity => "User Activity",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone)]
pub struct ForensicsConfig {
    pub case_id: String,
    pub examiner: String,
    pub evidence_sources: Vec<EvidenceType>,
    pub output_dir: String,
}

#[derive(Debug, Clone)]
pub struct EvidenceItem {
    pub id: String,
    pub description: String,
    pub hash_sha256: String,
    pub acquired_at: chrono::DateTime<chrono::Utc>,
    pub acquired_by: String,
}

#[derive(Debug, Clone)]
pub struct ChainOfCustody {
    pub case_id: String,
    pub items: Vec<EvidenceItem>,
}

#[derive(Debug, Clone)]
pub struct TimelineEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: String,
    pub description: String,
    pub source: String,
    pub artifact_category: ArtifactCategory,
}

#[derive(Debug, Clone)]
pub struct ForensicsCase {
    pub config: ForensicsConfig,
    pub chain_of_custody: ChainOfCustody,
    pub timeline: Vec<TimelineEntry>,
}

impl ForensicsCase {
    pub fn new(config: ForensicsConfig) -> Self {
        let case_id = config.case_id.clone();
        Self {
            config,
            chain_of_custody: ChainOfCustody {
                case_id,
                items: Vec::new(),
            },
            timeline: Vec::new(),
        }
    }
}

pub fn add_evidence(case: &mut ForensicsCase, item: EvidenceItem) {
    case.chain_of_custody.items.push(item);
}

pub fn add_timeline_entry(case: &mut ForensicsCase, entry: TimelineEntry) {
    case.timeline.push(entry);
    case.timeline.sort_by_key(|e| e.timestamp);
}

pub fn generate_forensics_report(case: &ForensicsCase) -> String {
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ");

    let evidence_rows = if case.chain_of_custody.items.is_empty() {
        "  _No evidence items recorded._".to_string()
    } else {
        case.chain_of_custody
            .items
            .iter()
            .map(|item| {
                format!(
                    "| {} | {} | `{}` | {} | {} |",
                    item.id,
                    item.description,
                    item.hash_sha256,
                    item.acquired_at.format("%Y-%m-%dT%H:%M:%SZ"),
                    item.acquired_by,
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let timeline_rows = if case.timeline.is_empty() {
        "  _No timeline entries recorded._".to_string()
    } else {
        case.timeline
            .iter()
            .map(|entry| {
                format!(
                    "| {} | {} | {} | {} | {} |",
                    entry.timestamp.format("%Y-%m-%dT%H:%M:%SZ"),
                    entry.event_type,
                    entry.description,
                    entry.source,
                    entry.artifact_category,
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        "# Forensics Case Report\n\n\
        **Case ID:** {case_id}\n\
        **Examiner:** {examiner}\n\
        **Report Generated:** {now}\n\n\
        ## Chain of Custody\n\n\
        | ID | Description | SHA-256 | Acquired At | Acquired By |\n\
        |----|-------------|---------|-------------|-------------|\n\
        {evidence_rows}\n\n\
        ## Timeline\n\n\
        | Timestamp | Event Type | Description | Source | Category |\n\
        |-----------|------------|-------------|--------|----------|\n\
        {timeline_rows}\n",
        case_id = case.config.case_id,
        examiner = case.config.examiner,
        now = now,
        evidence_rows = evidence_rows,
        timeline_rows = timeline_rows,
    )
}

impl EvidenceItem {
    pub fn new(description: &str, hash_sha256: &str, acquired_by: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            description: description.to_string(),
            hash_sha256: hash_sha256.to_string(),
            acquired_at: Utc::now(),
            acquired_by: acquired_by.to_string(),
        }
    }
}
