use crate::api::types::{AuditProvider, CheckResponse, ItemType};

pub fn show_item_summary(check: &CheckResponse) {
    let Some(item) = &check.item else {
        return;
    };

    let item_kind = match check.item_type.unwrap_or(ItemType::Server) {
        ItemType::Server => "MCP Server",
        ItemType::Skill => "Skill",
    };
    println!("Found: {} ({item_kind})", item.name);
    println!("  Identifier: {}", item.dedup_key);
    println!("  Description: {}", item.description);
    if let Some(url) = &item.github_url {
        println!("  GitHub: {url}");
    }
    if let Some(language) = &item.language {
        println!("  Language: {language}");
    }
    if let Some(stars) = item.stars {
        println!("  Stars: {stars}");
    }
}

pub fn show_audits(audits: &[AuditProvider]) {
    if audits.is_empty() {
        println!("Audits: none");
        return;
    }

    println!("Audits:");
    for audit in audits {
        let label = audit.provider_label.as_deref().unwrap_or(&audit.provider);
        let mut details = vec![format!("status={}", audit.status)];
        if let Some(grade) = &audit.grade {
            details.push(format!("grade={}", grade.to_uppercase()));
        }
        if let Some(score) = audit.score {
            details.push(format!("score={score:.1}"));
        }
        if let Some(security) = &audit.security_grade {
            details.push(format!("security={}", security.to_uppercase()));
        }
        if let Some(quality) = &audit.quality_grade {
            details.push(format!("quality={}", quality.to_uppercase()));
        }
        if let Some(license) = &audit.license_grade {
            details.push(format!("license={}", license.to_uppercase()));
        }

        println!("  - {label}: {}", details.join(", "));
        for message in &audit.messages {
            println!("    note: {message}");
        }
    }
}

pub fn show_provider_findings(audits: &[AuditProvider]) {
    let mut printed_header = false;
    for audit in audits {
        if audit.findings.is_empty() {
            continue;
        }

        if !printed_header {
            println!("Issues:");
            printed_header = true;
        }

        let label = audit.provider_label.as_deref().unwrap_or(&audit.provider);
        for finding in &audit.findings {
            let severity = finding
                .severity
                .as_deref()
                .unwrap_or("unknown")
                .to_uppercase();
            println!("  - {label} [{severity}]: {}", finding.message);
        }
    }
}

pub fn show_no_audit(request_count: i64, message: &str) {
    println!("No completed RunTheDev audit is available for this package.");
    println!("  Existing requests: {request_count}/10");
    println!("  {message}");
}

pub fn show_server_warning() {
    println!("Warning: Security or Quality signals indicate elevated risk.");
}

pub fn show_server_caution() {
    println!("No audits available. Install at your own risk. Be cautious.");
}
