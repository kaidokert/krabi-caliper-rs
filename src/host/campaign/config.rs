#[derive(Clone, Debug, Deserialize)]
pub struct ToolkitConfig {
    pub profiles: BTreeMap<String, RunnerProfile>,
    #[serde(default)]
    pub venues: BTreeMap<String, VenueConfig>,
    #[serde(default, rename = "case-sets")]
    pub case_sets: BTreeMap<String, Vec<CaseConfig>>,
    pub campaigns: BTreeMap<String, CampaignConfig>,
}

impl ToolkitConfig {
    /// Validates all declarative references and policies without building or running firmware.
    pub fn validate(&self) -> Result<(), CampaignError> {
        for name in self.profiles.keys() {
            self.resolve_profile(name)?;
        }
        for (name, campaign) in &self.campaigns {
            if !self.profiles.contains_key(&campaign.profile) {
                return Err(CampaignError::MissingProfile(campaign.profile.clone()));
            }
            if campaign.case_set.is_some() && !campaign.cases.is_empty() {
                return Err(CampaignError::InvalidConfig(format!(
                    "campaign {name:?} cannot specify both cases and case-set"
                )));
            }
            if let Some(case_set) = &campaign.case_set {
                if !self.case_sets.contains_key(case_set) {
                    return Err(CampaignError::InvalidConfig(format!(
                        "campaign {name:?} references unknown case-set {case_set:?}"
                    )));
                }
            }
            let cases = campaign.case_set.as_ref().map_or_else(
                || campaign.cases.as_slice(),
                |case_set| self.case_sets[case_set].as_slice(),
            );
            validate_cases(name, campaign, cases)?;
            for (axis, values) in &campaign.matrix {
                if values.is_empty() {
                    return Err(CampaignError::InvalidConfig(format!(
                        "campaign {name:?} matrix axis {axis:?} has no values"
                    )));
                }
            }
            validate_matrix_features(name, campaign)?;
            if let Some(policy) = &campaign.constant_time {
                validate_constant_time_config(policy)?;
            }
        }
        Ok(())
    }

    fn resolve_profile(&self, name: &str) -> Result<ResolvedRunnerProfile, CampaignError> {
        let mut visiting = Vec::new();
        let mut profile = self.inherited_profile(name, &mut visiting)?;
        let mut initial_evidence = BTreeMap::new();
        if let Some(raw_venue) = &mut profile.venue {
            let venue_secrets = self
                .venues
                .values()
                .flat_map(|venue| venue.secret_bindings.iter().cloned())
                .collect();
            reject_secret_placeholders(raw_venue, &venue_secrets, "profile venue")?;
            *raw_venue = expand_bindings(
                raw_venue,
                &BTreeMap::new(),
                &BTreeSet::new(),
                &mut initial_evidence,
            )?;
        }
        let venue = match profile.venue.as_deref() {
            Some(venue_name) => Some((
                venue_name,
                self.venues.get(venue_name).ok_or_else(|| {
                    CampaignError::InvalidConfig(format!(
                        "profile {name:?} references unknown venue {venue_name:?}"
                    ))
                })?,
            )),
            None => None,
        };
        profile.resolve(name, venue, initial_evidence)
    }

    fn inherited_profile(
        &self,
        name: &str,
        visiting: &mut Vec<String>,
    ) -> Result<RunnerProfile, CampaignError> {
        if visiting.iter().any(|value| value == name) {
            visiting.push(name.to_string());
            return Err(CampaignError::InvalidConfig(format!(
                "profile inheritance cycle: {}",
                visiting.join(" -> ")
            )));
        }
        let child = self
            .profiles
            .get(name)
            .ok_or_else(|| CampaignError::MissingProfile(name.to_string()))?;
        visiting.push(name.to_string());
        let result = if let Some(parent) = child.extends.as_deref() {
            let parent = self.inherited_profile(parent, visiting)?;
            child.merge_over(parent)
        } else {
            child.clone()
        };
        visiting.pop();
        Ok(result)
    }
}

fn validate_cases(
    campaign_name: &str,
    campaign: &CampaignConfig,
    cases: &[CaseConfig],
) -> Result<(), CampaignError> {
    if cases.is_empty() {
        return Err(CampaignError::InvalidConfig(format!(
            "campaign {campaign_name:?} has no cases"
        )));
    }
    let mut names = BTreeSet::new();
    for case in cases {
        if !names.insert(case.name.as_str()) {
            return Err(CampaignError::InvalidConfig(format!(
                "campaign {campaign_name:?} has duplicate case {:?}",
                case.name
            )));
        }
        match (&case.example, &case.binary) {
            (Some(_), None) | (None, Some(_)) => {}
            (Some(_), Some(_)) => {
                return Err(CampaignError::InvalidConfig(format!(
                    "case {:?} cannot specify both example and binary",
                    case.name
                )));
            }
            (None, None) => {
                return Err(CampaignError::InvalidConfig(format!(
                    "case {:?} requires example or binary",
                    case.name
                )));
            }
        }
    }
    if let Some(baseline) = campaign.baseline_case.as_deref() {
        validate_baseline(campaign_name, "campaign", baseline, &names)?;
    }
    for case in cases {
        if let Some(baseline) = case.baseline.as_deref() {
            validate_baseline(campaign_name, &case.name, baseline, &names)?;
        }
    }
    Ok(())
}

fn validate_baseline(
    campaign: &str,
    owner: &str,
    baseline: &str,
    names: &BTreeSet<&str>,
) -> Result<(), CampaignError> {
    if names.contains(baseline) {
        Ok(())
    } else {
        Err(CampaignError::InvalidConfig(format!(
            "campaign {campaign:?} baseline {baseline:?} referenced by {owner:?} is not a case"
        )))
    }
}

fn validate_matrix_features(
    campaign_name: &str,
    campaign: &CampaignConfig,
) -> Result<(), CampaignError> {
    for template in &campaign.matrix_features {
        let mut rest = template.as_str();
        while let Some(start) = rest.find('{') {
            if rest[..start].contains('}') {
                return Err(CampaignError::InvalidConfig(format!(
                    "campaign {campaign_name:?} has unmatched matrix placeholder in {template:?}"
                )));
            }
            let tail = &rest[start + 1..];
            let end = tail.find('}').ok_or_else(|| {
                CampaignError::InvalidConfig(format!(
                    "campaign {campaign_name:?} has unterminated matrix placeholder in {template:?}"
                ))
            })?;
            let axis = &tail[..end];
            if axis.is_empty() || !campaign.matrix.contains_key(axis) {
                return Err(CampaignError::InvalidConfig(format!(
                    "campaign {campaign_name:?} matrix feature references unknown axis {axis:?}"
                )));
            }
            rest = &tail[end + 1..];
        }
        if rest.contains('}') {
            return Err(CampaignError::InvalidConfig(format!(
                "campaign {campaign_name:?} has unmatched matrix placeholder in {template:?}"
            )));
        }
    }
    Ok(())
}

fn resolve_profile_bindings(
    profile: &mut ResolvedRunnerProfile,
    venue_bindings: &BTreeMap<String, String>,
    secret_bindings: &BTreeSet<String>,
    mut evidence: BTreeMap<String, String>,
) -> Result<(), CampaignError> {
    macro_rules! resolve {
        ($value:expr) => {
            *$value = expand_bindings($value, venue_bindings, secret_bindings, &mut evidence)?
        };
    }
    resolve!(&mut profile.target);
    if let Some(value) = &mut profile.toolchain {
        resolve!(value);
    }
    resolve!(&mut profile.cargo_profile);
    if let Some(value) = &mut profile.executable {
        resolve!(value);
    }
    for value in &mut profile.args {
        resolve!(value);
    }
    for command in &mut profile.prepare {
        resolve!(&mut command.executable);
        for value in &mut command.args {
            resolve!(value);
        }
    }
    for value in &mut profile.build_features {
        resolve!(value);
    }
    if let Some(value) = &mut profile.completion_marker {
        resolve!(value);
    }
    for value in [
        &mut profile.board,
        &mut profile.mcu,
        &mut profile.transport,
        &mut profile.probe,
        &mut profile.host_usb_path,
    ]
    .into_iter()
    .flatten()
    {
        resolve!(value);
    }
    if let Some(value) = &mut profile.target_dir {
        let expanded = expand_bindings(
            &value.to_string_lossy(),
            venue_bindings,
            secret_bindings,
            &mut evidence,
        )?;
        *value = PathBuf::from(expanded);
    }
    resolve!(&mut profile.artifact_extension);
    profile.resolved_bindings = evidence;
    Ok(())
}

fn expand_bindings(
    input: &str,
    venue_bindings: &BTreeMap<String, String>,
    secret_bindings: &BTreeSet<String>,
    evidence: &mut BTreeMap<String, String>,
) -> Result<String, CampaignError> {
    let mut output = String::new();
    let mut rest = input;
    while let Some(start) = rest.find("${") {
        output.push_str(&rest[..start]);
        let tail = &rest[start + 2..];
        let end = tail.find('}').ok_or_else(|| {
            CampaignError::InvalidConfig(format!("unterminated binding in {input:?}"))
        })?;
        let name = &tail[..end];
        if name.is_empty()
            || !name
                .bytes()
                .all(|value| value == b'_' || value.is_ascii_uppercase() || value.is_ascii_digit())
        {
            return Err(CampaignError::InvalidConfig(format!(
                "invalid binding name {name:?} in {input:?}"
            )));
        }
        let value = venue_bindings
            .get(name)
            .cloned()
            .or_else(|| std::env::var(name).ok())
            .ok_or_else(|| {
                CampaignError::InvalidConfig(format!(
                    "configuration requires binding {name}, but it is unset"
                ))
            })?;
        output.push_str(&value);
        evidence.insert(
            name.to_string(),
            if secret_bindings.contains(name) || binding_looks_secret(name) {
                "<redacted>".to_string()
            } else {
                value
            },
        );
        rest = &tail[end + 1..];
    }
    output.push_str(rest);
    Ok(output)
}

fn binding_looks_secret(name: &str) -> bool {
    [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "CREDENTIAL",
        "LICENSE",
        "PRIVATE_KEY",
    ]
    .iter()
    .any(|part| name.contains(part))
}

fn reject_secret_placeholders(
    input: &str,
    declared_secrets: &BTreeSet<String>,
    field: &str,
) -> Result<(), CampaignError> {
    let mut rest = input;
    while let Some(start) = rest.find("${") {
        let tail = &rest[start + 2..];
        let Some(end) = tail.find('}') else {
            break;
        };
        let name = &tail[..end];
        if declared_secrets.contains(name) || binding_looks_secret(name) {
            return Err(CampaignError::InvalidConfig(format!(
                "{field} must not contain secret binding {name}"
            )));
        }
        rest = &tail[end + 1..];
    }
    Ok(())
}

fn reject_identity_secrets(
    profile: &ResolvedRunnerProfile,
    secrets: &BTreeSet<String>,
) -> Result<(), CampaignError> {
    reject_secret_placeholders(&profile.target, secrets, "profile target")?;
    reject_secret_placeholders(&profile.cargo_profile, secrets, "profile cargo-profile")?;
    for (field, value) in [
        ("profile board", profile.board.as_deref()),
        ("profile mcu", profile.mcu.as_deref()),
        ("profile transport", profile.transport.as_deref()),
        ("profile probe", profile.probe.as_deref()),
        ("profile host-usb-path", profile.host_usb_path.as_deref()),
    ] {
        if let Some(value) = value {
            reject_secret_placeholders(value, secrets, field)?;
        }
    }
    Ok(())
}

fn configuration_identity(profile: &ResolvedRunnerProfile) -> String {
    format!(
        "target={};profile={};runner={:?};venue={};capabilities={};board={};mcu={};transport={};probe={};usb={};clock={};completion={:?};external={};timeout={};ct={:?};controlled={:?}",
        profile.target,
        profile.cargo_profile,
        profile.runner,
        profile.venue.as_deref().unwrap_or("none"),
        profile.capabilities.join(","),
        profile.board.as_deref().unwrap_or("unknown"),
        profile.mcu.as_deref().unwrap_or("unknown"),
        profile.transport.as_deref().unwrap_or("unknown"),
        profile.probe.as_deref().unwrap_or("unknown"),
        profile.host_usb_path.as_deref().unwrap_or("unknown"),
        profile
            .clock_frequency_hz
            .map_or_else(|| "unknown".to_string(), |value| value.to_string()),
        profile.completion_action,
        profile.require_external_measurements,
        profile.timeout_seconds,
        profile.constant_time,
        profile.controlled_environment,
    )
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VenueConfig {
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub bindings: BTreeMap<String, String>,
    #[serde(default)]
    pub secret_bindings: Vec<String>,
    #[serde(default)]
    pub controlled_environment: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RunnerProfile {
    #[serde(default)]
    pub extends: Option<String>,
    #[serde(default)]
    pub venue: Option<String>,
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default)]
    pub preset: Option<RunnerPreset>,
    #[serde(default)]
    pub runner: Option<RunnerKind>,
    #[serde(default)]
    pub target: Option<String>,
    /// Optional caller-owned Rust toolchain name, passed to Cargo and rustc.
    #[serde(default)]
    pub toolchain: Option<String>,
    #[serde(default)]
    pub cargo_profile: Option<String>,
    #[serde(default)]
    pub executable: Option<String>,
    #[serde(default)]
    pub args: Option<Vec<String>>,
    #[serde(default)]
    pub prepare: Option<Vec<RunnerCommandConfig>>,
    #[serde(default)]
    pub build_features: Option<Vec<String>>,
    #[serde(default)]
    pub completion_marker: Option<String>,
    #[serde(default)]
    pub completion_action: Option<CompletionAction>,
    #[serde(default)]
    pub board: Option<String>,
    #[serde(default)]
    pub mcu: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub probe: Option<String>,
    #[serde(default)]
    pub clock_frequency_hz: Option<ConfiguredU64>,
    #[serde(default)]
    pub host_usb_path: Option<String>,
    #[serde(default)]
    pub require_external_measurements: Option<bool>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub target_dir: Option<PathBuf>,
    #[serde(default)]
    pub artifact_extension: Option<String>,
    /// Optional host-side constant-time statistical gate.
    #[serde(default)]
    pub constant_time: Option<ConstantTimeConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum ConfiguredU64 {
    Number(u64),
    Binding(String),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConstantTimeConfig {
    #[serde(default = "default_welch_threshold")]
    pub welch_threshold: f64,
    #[serde(default = "default_minimum_samples_per_class")]
    pub minimum_samples_per_class: usize,
    /// Classes expected not to show a timing distinction.
    #[serde(default = "default_protected_classes")]
    pub protected_classes: Vec<String>,
    /// Positive controls expected to show a timing distinction.
    #[serde(default = "default_control_classes")]
    pub control_classes: Vec<String>,
    #[serde(default)]
    pub gate: bool,
}

const fn default_welch_threshold() -> f64 {
    super::DEFAULT_WELCH_THRESHOLD
}

const fn default_minimum_samples_per_class() -> usize {
    2
}

fn default_protected_classes() -> Vec<String> {
    vec!["positive".to_string()]
}

fn default_control_classes() -> Vec<String> {
    vec!["negative".to_string()]
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RunnerCommandConfig {
    pub executable: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum RunnerKind {
    Simavr,
    Command,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum RunnerPreset {
    QemuCortexM0,
    QemuCortexM3,
    QemuCortexM4,
    QemuRiscv32SifiveE,
    SimavrAtmega2560,
}

#[derive(Clone, Debug)]
struct ResolvedRunnerProfile {
    runner: RunnerKind,
    target: String,
    toolchain: Option<String>,
    cargo_profile: String,
    executable: Option<String>,
    args: Vec<String>,
    prepare: Vec<RunnerCommandConfig>,
    build_features: Vec<String>,
    completion_marker: Option<String>,
    completion_action: CompletionAction,
    board: Option<String>,
    mcu: Option<String>,
    transport: Option<String>,
    probe: Option<String>,
    clock_frequency_hz: Option<u64>,
    host_usb_path: Option<String>,
    require_external_measurements: bool,
    timeout_seconds: u64,
    target_dir: Option<PathBuf>,
    artifact_extension: String,
    constant_time: Option<ConstantTimeConfig>,
    venue: Option<String>,
    capabilities: Vec<String>,
    resolved_bindings: BTreeMap<String, String>,
    controlled_environment: BTreeMap<String, String>,
    configuration_identity: String,
}

impl RunnerProfile {
    fn merge_over(&self, mut parent: RunnerProfile) -> RunnerProfile {
        macro_rules! inherit_option {
            ($field:ident) => {
                if self.$field.is_some() {
                    parent.$field = self.$field.clone();
                }
            };
        }
        inherit_option!(venue);
        inherit_option!(preset);
        inherit_option!(runner);
        inherit_option!(target);
        inherit_option!(toolchain);
        inherit_option!(cargo_profile);
        inherit_option!(executable);
        inherit_option!(args);
        inherit_option!(prepare);
        inherit_option!(build_features);
        inherit_option!(completion_marker);
        inherit_option!(completion_action);
        inherit_option!(board);
        inherit_option!(mcu);
        inherit_option!(transport);
        inherit_option!(probe);
        inherit_option!(clock_frequency_hz);
        inherit_option!(host_usb_path);
        inherit_option!(require_external_measurements);
        inherit_option!(timeout_seconds);
        inherit_option!(target_dir);
        inherit_option!(artifact_extension);
        inherit_option!(constant_time);
        let mut requirements = parent.requires.into_iter().collect::<BTreeSet<_>>();
        requirements.extend(self.requires.iter().cloned());
        parent.requires = requirements.into_iter().collect();
        parent.extends = None;
        parent
    }

    fn resolve(
        &self,
        profile_name: &str,
        venue: Option<(&str, &VenueConfig)>,
        mut initial_evidence: BTreeMap<String, String>,
    ) -> Result<ResolvedRunnerProfile, CampaignError> {
        if let Some(policy) = &self.constant_time {
            validate_constant_time_config(policy)?;
        }
        let preset = self.preset.map(preset_values);
        let runner = self
            .runner
            .or_else(|| preset.as_ref().map(|value| value.runner))
            .ok_or_else(|| {
                CampaignError::InvalidConfig("runner profile requires runner or preset".to_string())
            })?;
        let target = self
            .target
            .clone()
            .or_else(|| preset.as_ref().map(|value| value.target.to_string()))
            .ok_or_else(|| {
                CampaignError::InvalidConfig("runner profile requires target or preset".to_string())
            })?;
        let executable = self
            .executable
            .clone()
            .or_else(|| preset.as_ref().map(|value| value.executable.to_string()));
        let args = if self.args.is_none() {
            preset
                .as_ref()
                .map_or_else(Vec::new, |value| strings(value.args))
        } else {
            self.args.clone().unwrap_or_default()
        };
        let completion_marker = self.completion_marker.clone().or_else(|| {
            preset
                .as_ref()
                .and_then(|value| value.completion_marker.map(ToString::to_string))
        });
        let artifact_extension = self.artifact_extension.clone().unwrap_or_else(|| {
            preset
                .as_ref()
                .map_or_else(elf_extension, |value| value.artifact_extension.to_string())
        });
        let (venue_name, venue_config) = venue.map_or((None, None), |(name, config)| {
            (Some(name.to_string()), Some(config))
        });
        let available = venue_config
            .map(|value| value.capabilities.iter().cloned().collect::<BTreeSet<_>>())
            .unwrap_or_default();
        let required = self.requires.iter().cloned().collect::<BTreeSet<_>>();
        let missing = required
            .iter()
            .filter(|required| !available.contains(*required))
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(CampaignError::InvalidConfig(format!(
                "profile {profile_name:?} requires unavailable capabilities: {}",
                missing.join(", ")
            )));
        }
        let bindings = venue_config
            .map(|value| value.bindings.clone())
            .unwrap_or_default();
        let secrets: BTreeSet<String> = venue_config
            .map(|value| value.secret_bindings.iter().cloned().collect())
            .unwrap_or_default();
        let mut controlled = venue_config
            .map(|value| value.controlled_environment.clone())
            .unwrap_or_default();
        for value in controlled.values_mut() {
            reject_secret_placeholders(value, &secrets, "controlled-environment")?;
            *value = expand_bindings(value, &bindings, &secrets, &mut initial_evidence)?;
        }
        let clock_frequency_hz = match &self.clock_frequency_hz {
            Some(ConfiguredU64::Number(value)) => Some(*value),
            Some(ConfiguredU64::Binding(value)) => {
                reject_secret_placeholders(value, &secrets, "profile clock-frequency-hz")?;
                let expanded = expand_bindings(value, &bindings, &secrets, &mut initial_evidence)?;
                Some(expanded.parse::<u64>().map_err(|_| {
                    CampaignError::InvalidConfig(format!(
                        "clock-frequency-hz resolved to non-integer {expanded:?}"
                    ))
                })?)
            }
            None => preset.as_ref().and_then(|value| value.clock_frequency_hz),
        };
        let mut resolved = ResolvedRunnerProfile {
            runner,
            target,
            toolchain: self.toolchain.clone(),
            cargo_profile: self.cargo_profile.clone().unwrap_or_else(release_profile),
            executable,
            args,
            prepare: self.prepare.clone().unwrap_or_default(),
            build_features: self.build_features.clone().unwrap_or_default(),
            completion_marker,
            completion_action: self.completion_action.unwrap_or_default(),
            board: self.board.clone().or_else(|| {
                preset
                    .as_ref()
                    .and_then(|value| value.board.map(str::to_string))
            }),
            mcu: self.mcu.clone().or_else(|| {
                preset
                    .as_ref()
                    .and_then(|value| value.mcu.map(str::to_string))
            }),
            transport: self.transport.clone().or_else(|| {
                preset
                    .as_ref()
                    .and_then(|value| value.transport.map(str::to_string))
            }),
            probe: self.probe.clone(),
            clock_frequency_hz,
            host_usb_path: self.host_usb_path.clone(),
            require_external_measurements: self.require_external_measurements.unwrap_or(false),
            timeout_seconds: self.timeout_seconds.unwrap_or_else(default_timeout_seconds),
            target_dir: self.target_dir.clone(),
            artifact_extension,
            constant_time: self.constant_time.clone(),
            venue: venue_name,
            capabilities: required.into_iter().collect(),
            resolved_bindings: BTreeMap::new(),
            controlled_environment: controlled,
            configuration_identity: String::new(),
        };
        reject_identity_secrets(&resolved, &secrets)?;
        resolve_profile_bindings(&mut resolved, &bindings, &secrets, initial_evidence)?;
        resolved.configuration_identity = configuration_identity(&resolved);
        Ok(resolved)
    }
}

fn validate_constant_time_config(policy: &ConstantTimeConfig) -> Result<(), CampaignError> {
    if !policy.welch_threshold.is_finite() || policy.welch_threshold < 0.0 {
        return Err(CampaignError::InvalidConfig(
            "constant-time welch-threshold must be finite and non-negative".to_string(),
        ));
    }
    if policy.minimum_samples_per_class < 2 {
        return Err(CampaignError::InvalidConfig(
            "constant-time minimum-samples-per-class must be at least 2".to_string(),
        ));
    }
    if policy.protected_classes.is_empty() {
        return Err(CampaignError::InvalidConfig(
            "constant-time protected-classes must not be empty".to_string(),
        ));
    }
    if policy
        .protected_classes
        .iter()
        .any(|class| policy.control_classes.contains(class))
    {
        return Err(CampaignError::InvalidConfig(
            "constant-time protected and control classes must be disjoint".to_string(),
        ));
    }
    Ok(())
}

struct PresetValues {
    runner: RunnerKind,
    target: &'static str,
    executable: &'static str,
    args: &'static [&'static str],
    completion_marker: Option<&'static str>,
    artifact_extension: &'static str,
    board: Option<&'static str>,
    mcu: Option<&'static str>,
    transport: Option<&'static str>,
    clock_frequency_hz: Option<u64>,
}

fn preset_values(preset: RunnerPreset) -> PresetValues {
    match preset {
        RunnerPreset::QemuCortexM0 => PresetValues {
            runner: RunnerKind::Command,
            target: "thumbv6m-none-eabi",
            executable: "qemu-system-arm",
            args: &[
                "-cpu",
                "cortex-m0",
                "-machine",
                "microbit",
                "-nographic",
                "-semihosting-config",
                "enable=on,target=native",
                "-kernel",
                "{artifact}",
            ],
            completion_marker: None,
            artifact_extension: "",
            board: Some("qemu-microbit"),
            mcu: Some("nrf51822"),
            transport: Some("semihosting"),
            clock_frequency_hz: None,
        },
        RunnerPreset::QemuCortexM3 => PresetValues {
            runner: RunnerKind::Command,
            target: "thumbv7m-none-eabi",
            executable: "qemu-system-arm",
            args: &[
                "-cpu",
                "cortex-m3",
                "-machine",
                "lm3s6965evb",
                "-nographic",
                "-semihosting-config",
                "enable=on,target=native",
                "-kernel",
                "{artifact}",
            ],
            completion_marker: None,
            artifact_extension: "",
            board: Some("qemu-lm3s6965evb"),
            mcu: Some("lm3s6965"),
            transport: Some("semihosting"),
            clock_frequency_hz: None,
        },
        RunnerPreset::QemuCortexM4 => PresetValues {
            runner: RunnerKind::Command,
            target: "thumbv7em-none-eabi",
            executable: "qemu-system-arm",
            args: &[
                "-cpu",
                "cortex-m4",
                "-machine",
                "netduinoplus2",
                "-nographic",
                "-semihosting-config",
                "enable=on,target=native",
                "-kernel",
                "{artifact}",
            ],
            completion_marker: None,
            artifact_extension: "",
            board: Some("qemu-netduinoplus2"),
            mcu: Some("stm32f405rg"),
            transport: Some("semihosting"),
            clock_frequency_hz: None,
        },
        RunnerPreset::QemuRiscv32SifiveE => PresetValues {
            runner: RunnerKind::Command,
            target: "riscv32imac-unknown-none-elf",
            executable: "qemu-system-riscv32",
            args: &[
                "-nographic",
                "-machine",
                "sifive_e",
                "-bios",
                "none",
                "-kernel",
                "{artifact}",
            ],
            completion_marker: Some("EM_OUTCOME"),
            artifact_extension: "",
            board: Some("qemu-sifive-e"),
            mcu: Some("sifive-e31"),
            transport: Some("uart"),
            clock_frequency_hz: None,
        },
        RunnerPreset::SimavrAtmega2560 => PresetValues {
            runner: RunnerKind::Simavr,
            target: "avr-none",
            executable: "simavr",
            args: &["-m", "atmega2560", "-f", "16000000"],
            completion_marker: Some("status:PASS"),
            artifact_extension: "elf",
            board: Some("simavr-atmega2560"),
            mcu: Some("atmega2560"),
            transport: Some("uart"),
            clock_frequency_hz: Some(16_000_000),
        },
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
}

fn release_profile() -> String {
    "release".to_string()
}

const fn default_timeout_seconds() -> u64 {
    60
}

fn elf_extension() -> String {
    "elf".to_string()
}
