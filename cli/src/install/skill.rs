use std::path::PathBuf;

use dialoguer::{MultiSelect, theme::ColorfulTheme};

use crate::api::types::{CheckItem, SkillDetailResponse};
use crate::clients::{OperatingSystem, home_dir};
use crate::install::writer::write_atomic;
use crate::{CliError, CliResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillTarget {
    ClaudeCode,
    Codex,
    OpenCode,
}

impl SkillTarget {
    pub fn id(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::OpenCode => "opencode",
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "Claude Code",
            Self::Codex => "Codex",
            Self::OpenCode => "OpenCode",
        }
    }

    pub fn supports_os(self, os: OperatingSystem) -> bool {
        match os {
            OperatingSystem::MacOS | OperatingSystem::Linux => true,
            OperatingSystem::Other => false,
        }
    }

    fn skill_file_path(self, os: OperatingSystem, skill_name: &str) -> CliResult<PathBuf> {
        if !self.supports_os(os) {
            return Err(CliError::Operational(format!(
                "{} skill install is unsupported on this platform",
                self.display_name()
            )));
        }

        let home = home_dir()?;
        let path = match self {
            Self::ClaudeCode => home
                .join(".claude")
                .join("skills")
                .join(skill_name)
                .join("SKILL.md"),
            Self::Codex => home
                .join(".agents")
                .join("skills")
                .join(skill_name)
                .join("SKILL.md"),
            Self::OpenCode => home
                .join(".config")
                .join("opencode")
                .join("skills")
                .join(skill_name)
                .join("SKILL.md"),
        };

        Ok(path)
    }
}

#[derive(Debug, Clone)]
pub struct SkillInstallPlan {
    pub skill_name: String,
    pub content: String,
}

pub enum SkillInstallOutcome {
    Installed { target: String, path: PathBuf },
    Failed { target: String, reason: String },
}

const SKILL_TARGETS: [SkillTarget; 3] = [
    SkillTarget::ClaudeCode,
    SkillTarget::Codex,
    SkillTarget::OpenCode,
];

pub fn choose_skill_targets(os: OperatingSystem, interactive: bool) -> CliResult<Vec<SkillTarget>> {
    let supported: Vec<SkillTarget> = SKILL_TARGETS
        .iter()
        .copied()
        .filter(|target| target.supports_os(os))
        .collect();

    if supported.is_empty() {
        return Ok(Vec::new());
    }

    if !interactive {
        return Ok(supported);
    }

    let labels: Vec<&str> = supported
        .iter()
        .map(|target| target.display_name())
        .collect();
    let selected = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Install skill to")
        .items(&labels)
        .interact()
        .map_err(|err| CliError::Operational(format!("failed to select skill targets: {err}")))?;

    Ok(selected
        .into_iter()
        .filter_map(|idx| supported.get(idx).copied())
        .collect())
}

pub fn build_skill_install_plan(
    item: &CheckItem,
    detail: &SkillDetailResponse,
) -> CliResult<SkillInstallPlan> {
    let skill_name = resolve_skill_name(item, detail).ok_or_else(|| {
        CliError::Operational("failed to derive a valid local skill name".to_string())
    })?;

    let description = normalize_description(&detail.description, &item.description);
    let body = normalize_skill_body(detail, item);
    let content = format_skill_markdown(&skill_name, &description, &body);

    Ok(SkillInstallPlan {
        skill_name,
        content,
    })
}

pub fn install_skill_to_targets(
    plan: &SkillInstallPlan,
    os: OperatingSystem,
    targets: Vec<SkillTarget>,
) -> Vec<SkillInstallOutcome> {
    let mut outcomes = Vec::with_capacity(targets.len());

    for target in targets {
        let result = target
            .skill_file_path(os, &plan.skill_name)
            .and_then(|path| {
                write_atomic(&path, &plan.content)?;
                Ok(path)
            })
            .map(|path| SkillInstallOutcome::Installed {
                target: target.display_name().to_string(),
                path,
            })
            .unwrap_or_else(|err| SkillInstallOutcome::Failed {
                target: target.display_name().to_string(),
                reason: err.to_string(),
            });

        outcomes.push(result);
    }

    outcomes
}

fn resolve_skill_name(item: &CheckItem, detail: &SkillDetailResponse) -> Option<String> {
    [
        detail.skill_name.as_str(),
        detail.name.as_str(),
        item.name.as_str(),
        detail.dedup_key.split('/').next_back().unwrap_or(""),
    ]
    .iter()
    .filter_map(|candidate| sanitize_skill_name(candidate))
    .next()
}

fn sanitize_skill_name(value: &str) -> Option<String> {
    let mut out = String::new();
    let mut prev_dash = false;

    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
            continue;
        }

        if matches!(ch, '-' | '_' | ' ' | '/' | '.' | ':') {
            if !prev_dash && !out.is_empty() {
                out.push('-');
                prev_dash = true;
            }
            continue;
        }
    }

    while out.ends_with('-') {
        out.pop();
    }

    if out.len() > 64 {
        out.truncate(64);
        while out.ends_with('-') {
            out.pop();
        }
    }

    if out.is_empty() {
        return None;
    }

    Some(out)
}

fn normalize_description(primary: &str, fallback: &str) -> String {
    let source = if !primary.trim().is_empty() {
        primary
    } else {
        fallback
    };

    let collapsed = source.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return "Installable skill from RunTheDev registry.".to_string();
    }

    if collapsed.len() <= 300 {
        return collapsed;
    }

    collapsed.chars().take(300).collect()
}

fn normalize_skill_body(detail: &SkillDetailResponse, item: &CheckItem) -> String {
    if let Some(content) = detail.skill_md_content.as_deref() {
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    let mut lines = vec![
        format!("# {}", item.name),
        String::new(),
        item.description.clone(),
    ];
    if let Some(url) = detail.github_url.as_ref().or(item.github_url.as_ref()) {
        lines.push(String::new());
        lines.push(format!("Source: {url}"));
    }

    lines.join("\n")
}

fn format_skill_markdown(name: &str, description: &str, body: &str) -> String {
    let escaped_description = yaml_escape(description);
    format!("---\nname: {name}\ndescription: \"{escaped_description}\"\n---\n\n{body}\n")
}

fn yaml_escape(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::sanitize_skill_name;

    #[test]
    fn sanitize_skill_name_normalizes_symbols() {
        let value = sanitize_skill_name("My Skill/Name_v2");
        assert_eq!(value.as_deref(), Some("my-skill-name-v2"));
    }

    #[test]
    fn sanitize_skill_name_rejects_empty_after_cleanup() {
        let value = sanitize_skill_name("---");
        assert!(value.is_none());
    }
}
