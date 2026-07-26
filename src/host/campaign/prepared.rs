const PREPARED_CAMPAIGN_SCHEMA: u32 = 1;
const PREPARED_OUTPUT_MARKER: &str = ".krabi-caliper-prepared";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreparedCampaign {
    pub schema: u32,
    pub campaign: String,
    pub profile: String,
    pub source: SourceMetadata,
    pub build: BuildMetadata,
    #[serde(default)]
    pub constant_time: Option<ConstantTimeConfig>,
    pub cases: Vec<PreparedCase>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreparedCase {
    pub case: ExpandedCase,
    pub artifact: PathBuf,
    pub sha256: String,
    pub footprint: Option<ElfFootprint>,
    pub build_command: String,
    pub build_duration_ms: u128,
}

#[derive(Clone, Debug)]
struct ResolvedBuildProfile {
    target: String,
    toolchain: Option<String>,
    cargo_profile: String,
    target_dir: Option<PathBuf>,
    artifact_extension: String,
    build_features: Vec<String>,
}

impl ToolkitConfig {
    fn resolve_build_profile(
        &self,
        name: &str,
    ) -> Result<ResolvedBuildProfile, CampaignError> {
        let mut visiting = Vec::new();
        let profile = self.inherited_profile(name, &mut visiting)?;
        let preset = profile.preset.map(preset_values);
        let mut evidence = BTreeMap::new();
        let mut expand = |value: &str| {
            expand_bindings(
                value,
                &BTreeMap::new(),
                &BTreeSet::new(),
                &mut evidence,
            )
        };
        let target = profile
            .target
            .as_deref()
            .map(&mut expand)
            .transpose()?
            .or_else(|| preset.as_ref().map(|value| value.target.to_string()))
            .ok_or_else(|| {
                CampaignError::InvalidConfig("runner profile requires target or preset".to_string())
            })?;
        let toolchain = profile
            .toolchain
            .as_deref()
            .map(&mut expand)
            .transpose()?;
        let cargo_profile = expand(
            &profile
                .cargo_profile
                .clone()
                .unwrap_or_else(release_profile),
        )?;
        let target_dir = profile
            .target_dir
            .as_ref()
            .map(|value| expand(&value.to_string_lossy()).map(PathBuf::from))
            .transpose()?;
        let artifact_extension = profile
            .artifact_extension
            .as_deref()
            .map(&mut expand)
            .transpose()?
            .unwrap_or_else(|| {
                preset
                    .as_ref()
                    .map_or_else(elf_extension, |value| value.artifact_extension.to_string())
            });
        let build_features = profile
            .build_features
            .unwrap_or_default()
            .iter()
            .map(|value| expand(value))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ResolvedBuildProfile {
            target,
            toolchain,
            cargo_profile,
            target_dir,
            artifact_extension,
            build_features,
        })
    }
}

fn prepared_sha256(path: &Path) -> Result<String, CampaignError> {
    use sha2::{Digest, Sha256};

    let bytes = fs::read(path).map_err(|source| CampaignError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub fn read_prepared_campaign(path: &Path) -> Result<PreparedCampaign, CampaignError> {
    let bytes = fs::read(path).map_err(|source| CampaignError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let prepared: PreparedCampaign = serde_json::from_slice(&bytes)
        .map_err(|error| CampaignError::InvalidConfig(error.to_string()))?;
    if prepared.schema != PREPARED_CAMPAIGN_SCHEMA {
        return Err(CampaignError::InvalidConfig(format!(
            "unsupported prepared campaign schema {}",
            prepared.schema
        )));
    }
    Ok(prepared)
}
