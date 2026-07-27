#[derive(Clone, Debug, Default)]
pub struct CampaignSelection {
    pub quick: bool,
    pub cases: Vec<String>,
    pub silent: bool,
}

pub struct CampaignExecutor {
    runner: CommandRunner,
}

struct RunContext<'a> {
    environment: &'a ReproducibilityMetadata,
    silent: bool,
}

impl Default for CampaignExecutor {
    fn default() -> Self {
        Self {
            runner: CommandRunner,
        }
    }
}

impl CampaignExecutor {
    pub fn build_prepared(
        &self,
        config: &ToolkitConfig,
        campaign_name: &str,
        workspace: &Path,
        selection: &CampaignSelection,
        output_dir: &Path,
    ) -> Result<PathBuf, CampaignError> {
        config.validate_for_build()?;
        let (campaign, mut cases) = selected_campaign(config, campaign_name, selection)?;
        let mut profile = config.resolve_build_profile(&campaign.profile)?;
        if profile.target == "host" {
            profile.target = host_target(workspace, profile.toolchain.as_deref()).ok_or_else(|| {
                CampaignError::InvalidConfig(
                    "target=host requires a discoverable rustc host triple".to_string(),
                )
            })?;
        }
        let constant_time = effective_constant_time(config, &campaign)?;
        let output_dir = safe_prepared_output(workspace, output_dir)?;
        for case in &mut cases {
            let mut features = profile.build_features.clone();
            features.append(&mut case.features);
            features.sort();
            features.dedup();
            case.features = features;
        }
        let source = SourceMetadata {
            workspace: None,
            repository: command_value(
                workspace,
                "git",
                &["remote", "get-url", "origin"],
                selection.silent,
            ),
            git_commit: command_value(
                workspace,
                "git",
                &["rev-parse", "HEAD"],
                selection.silent,
            ),
            dirty: git_dirty_excluding_path(workspace, &output_dir, selection.silent),
        };
        if source.git_commit.is_none() || source.dirty != Some(false) {
            return Err(CampaignError::InvalidConfig(
                "prepared campaigns require a clean Git commit".to_string(),
            ));
        }
        let build = BuildMetadata {
            toolchain: profile.toolchain.clone(),
            rustc: command_value_with_toolchain(
                workspace,
                "rustc",
                &["--version"],
                profile.toolchain.as_deref(),
                selection.silent,
            ),
            cargo: command_value_with_toolchain(
                workspace,
                "cargo",
                &["--version"],
                profile.toolchain.as_deref(),
                selection.silent,
            ),
            target: Some(profile.target.clone()),
            optimization: Some(profile.cargo_profile.clone()),
            features: Vec::new(),
        };
        reset_prepared_output(&output_dir)?;
        fs::create_dir_all(&output_dir).map_err(|source| CampaignError::Io {
            path: output_dir.clone(),
            source,
        })?;
        write_text(&output_dir.join(PREPARED_OUTPUT_MARKER), "krabi-caliper\n")?;
        let mut prepared_cases = Vec::new();
        for case in cases {
            let case_dir = artifact_child(&output_dir, &case.id, "expanded case id")?;
            fs::create_dir_all(&case_dir).map_err(|source| CampaignError::Io {
                path: case_dir.clone(),
                source,
            })?;
            let spec = prepared_cargo_build_spec(&profile, workspace, &case)
                .silent(selection.silent);
            let build_command = spec.display();
            let output = self.runner.run(&spec)?;
            write_bytes(&case_dir.join("build-stdout.log"), &output.stdout)?;
            write_bytes(&case_dir.join("build-stderr.log"), &output.stderr)?;
            if !output.success() {
                return Err(CampaignError::InvalidConfig(command_failure_reason(
                    "build command",
                    &output,
                )));
            }
            let artifact = artifact_from_build_output(&case, &output.stdout)?;
            let filename = if profile.artifact_extension.is_empty() {
                "firmware".to_string()
            } else {
                format!("firmware.{}", profile.artifact_extension)
            };
            let retained = case_dir.join(filename);
            fs::copy(&artifact, &retained).map_err(|source| CampaignError::Io {
                path: retained.clone(),
                source,
            })?;
            prepared_cases.push(PreparedCase {
                case,
                artifact: retained
                    .strip_prefix(&output_dir)
                    .unwrap_or(&retained)
                    .to_path_buf(),
                sha256: prepared_sha256(&retained)?,
                footprint: artifact_footprint(&retained)?,
                build_command,
                build_duration_ms: output.duration.as_millis(),
            });
        }
        let prepared = PreparedCampaign {
            schema: PREPARED_CAMPAIGN_SCHEMA,
            campaign: campaign_name.to_string(),
            profile: campaign.profile,
            source,
            build,
            constant_time,
            cases: prepared_cases,
        };
        let manifest = output_dir.join("manifest.json");
        write_text(
            &manifest,
            &serde_json::to_string_pretty(&prepared)
                .map_err(|error| CampaignError::InvalidConfig(error.to_string()))?,
        )?;
        Ok(manifest)
    }

    pub fn run(
        &self,
        config: &ToolkitConfig,
        campaign_name: &str,
        workspace: &Path,
        selection: &CampaignSelection,
    ) -> Result<CampaignReport, CampaignError> {
        config.validate()?;
        let campaign = config
            .campaigns
            .get(campaign_name)
            .ok_or_else(|| CampaignError::MissingCampaign(campaign_name.to_string()))?;
        let mut campaign = campaign.clone();
        if let Some(case_set) = &campaign.case_set {
            if !campaign.cases.is_empty() {
                return Err(CampaignError::InvalidConfig(format!(
                    "campaign {campaign_name:?} cannot specify both cases and case-set"
                )));
            }
            campaign.cases = config.case_sets.get(case_set).cloned().ok_or_else(|| {
                CampaignError::InvalidConfig(format!("unknown case-set {case_set:?}"))
            })?;
        }
        let mut profile = config.resolve_profile(&campaign.profile)?;
        if profile.target == "host" {
            profile.target = host_target(workspace, profile.toolchain.as_deref()).ok_or_else(|| {
                CampaignError::InvalidConfig(
                    "target=host requires a discoverable rustc host triple".to_string(),
                )
            })?;
            profile.configuration_identity = configuration_identity(&profile);
        }
        if let Some(policy) = &campaign.constant_time {
            validate_constant_time_config(policy)?;
            profile.constant_time = Some(policy.clone());
        }
        let environment = self.collect_environment(workspace, &profile, selection.silent);
        let mut cases = expand_cases(&campaign, selection)?;
        for case in &mut cases {
            let mut features = profile.build_features.clone();
            features.append(&mut case.features);
            features.sort();
            features.dedup();
            case.features = features;
        }
        let artifact_root = workspace.join(
            campaign
                .artifact_dir
                .clone()
                .unwrap_or_else(|| PathBuf::from("target/krabi-caliper")),
        );
        let campaign_dir = artifact_child(&artifact_root, campaign_name, "campaign name")?;
        let mut reports = Vec::new();
        for case in cases {
            let report = self.run_case(
                (campaign_name, &campaign.profile),
                &profile,
                workspace,
                &campaign_dir,
                &case,
                RunContext {
                    environment: &environment,
                    silent: selection.silent,
                },
            )?;
            let passed = report.status == CaseStatus::Pass;
            reports.push(report);
            if !passed && !campaign.continue_on_failure {
                break;
            }
        }
        let report = CampaignReport {
            campaign: campaign_name.to_string(),
            profile: campaign.profile.clone(),
            cases: reports,
        };
        write_campaign_artifacts(&campaign_dir, &report)?;
        Ok(report)
    }

    pub fn run_prepared(
        &self,
        config: &ToolkitConfig,
        campaign_name: &str,
        workspace: &Path,
        selection: &CampaignSelection,
        manifest_path: &Path,
    ) -> Result<CampaignReport, CampaignError> {
        config.validate()?;
        let prepared = read_prepared_campaign(manifest_path)?;
        if prepared.campaign != campaign_name {
            return Err(CampaignError::InvalidConfig(format!(
                "prepared campaign is {:?}, not {campaign_name:?}",
                prepared.campaign
            )));
        }
        let (campaign, mut cases) = selected_campaign(config, campaign_name, selection)?;
        if prepared.profile != campaign.profile {
            return Err(CampaignError::InvalidConfig(
                "prepared campaign profile does not match configuration".to_string(),
            ));
        }
        let mut profile = config.resolve_profile(&campaign.profile)?;
        if profile.target == "host" {
            profile.target = host_target(workspace, profile.toolchain.as_deref()).ok_or_else(|| {
                CampaignError::InvalidConfig(
                    "target=host requires a discoverable rustc host triple".to_string(),
                )
            })?;
            profile.configuration_identity = configuration_identity(&profile);
        }
        if let Some(policy) = &campaign.constant_time {
            profile.constant_time = Some(policy.clone());
        }
        validate_prepared_build(&prepared, &profile)?;
        for case in &mut cases {
            let mut features = profile.build_features.clone();
            features.append(&mut case.features);
            features.sort();
            features.dedup();
            case.features = features;
        }
        if cases.len() != prepared.cases.len()
            || cases
                .iter()
                .zip(&prepared.cases)
                .any(|(case, prepared)| case != &prepared.case)
        {
            return Err(CampaignError::InvalidConfig(
                "prepared cases do not match the selected campaign".to_string(),
            ));
        }
        let commit = command_value(
            workspace,
            "git",
            &["rev-parse", "HEAD"],
            selection.silent,
        );
        let dirty = git_dirty_excluding(workspace, manifest_path, selection.silent);
        if commit != prepared.source.git_commit || dirty != Some(false) {
            return Err(CampaignError::InvalidConfig(
                "prepared source does not match the clean execution checkout".to_string(),
            ));
        }
        let environment = self.collect_environment(workspace, &profile, selection.silent);
        let manifest_dir = manifest_directory(manifest_path);
        let canonical_manifest_dir =
            manifest_dir
                .canonicalize()
                .map_err(|source| CampaignError::Io {
                    path: manifest_dir.to_path_buf(),
                    source,
                })?;
        let artifact_root = workspace.join(
            campaign
                .artifact_dir
                .clone()
                .unwrap_or_else(|| PathBuf::from("target/krabi-caliper")),
        );
        let campaign_dir = artifact_child(&artifact_root, campaign_name, "campaign name")?;
        let mut reports = Vec::new();
        for prepared_case in &prepared.cases {
            let artifact = manifest_dir.join(&prepared_case.artifact);
            let canonical_artifact =
                artifact
                    .canonicalize()
                    .map_err(|source| CampaignError::Io {
                        path: artifact.clone(),
                        source,
                    })?;
            if !canonical_artifact.starts_with(&canonical_manifest_dir)
                || !canonical_artifact.is_file()
                || prepared_sha256(&canonical_artifact)? != prepared_case.sha256
            {
                return Err(CampaignError::InvalidConfig(format!(
                    "prepared artifact for {:?} is missing or has the wrong digest",
                    prepared_case.case.id
                )));
            }
            let mut case_environment = environment.clone();
            case_environment.source = prepared.source.clone();
            case_environment.build = prepared.build.clone();
            case_environment.build.features = prepared_case.case.features.clone();
            let report = self.run_prepared_case(
                (campaign_name, &campaign.profile),
                &profile,
                workspace,
                &campaign_dir,
                prepared_case,
                &canonical_artifact,
                case_environment,
                selection.silent,
            )?;
            let passed = report.status == CaseStatus::Pass;
            reports.push(report);
            if !passed && !campaign.continue_on_failure {
                break;
            }
        }
        let report = CampaignReport {
            campaign: campaign_name.to_string(),
            profile: campaign.profile,
            cases: reports,
        };
        write_campaign_artifacts(&campaign_dir, &report)?;
        Ok(report)
    }

    fn run_case(
        &self,
        run_identity: (&str, &str),
        profile: &ResolvedRunnerProfile,
        workspace: &Path,
        campaign_dir: &Path,
        case: &ExpandedCase,
        context: RunContext<'_>,
    ) -> Result<CaseReport, CampaignError> {
        let mut environment = context.environment.clone();
        let silent = context.silent;
        environment.build.features = case.features.clone();
        let (campaign_name, profile_name) = run_identity;
        let case_dir = artifact_child(campaign_dir, &case.id, "expanded case id")?;
        if case_dir.exists() {
            fs::remove_dir_all(&case_dir).map_err(|source| CampaignError::Io {
                path: case_dir.clone(),
                source,
            })?;
        }
        fs::create_dir_all(&case_dir).map_err(|source| CampaignError::Io {
            path: case_dir.clone(),
            source,
        })?;
        let build = cargo_build_spec(profile, workspace, case).silent(silent);
        let build_display = build.display();
        let build_output = self.runner.run(&build)?;
        write_bytes(&case_dir.join("build-stdout.log"), &build_output.stdout)?;
        write_bytes(&case_dir.join("build-stderr.log"), &build_output.stderr)?;
        if !build_output.success() {
            let status = if build_output.timed_out {
                CaseStatus::TimedOut
            } else {
                CaseStatus::BuildFailed
            };
            let report = CaseReport {
                id: case.id.clone(),
                name: case.name.clone(),
                cargo_target: case.cargo_target.clone(),
                environment,
                features: case.features.clone(),
                parameters: case.parameters.clone(),
                artifact: None,
                footprint: None,
                baseline: case.baseline.clone(),
                build_command: build_display,
                prepare_commands: Vec::new(),
                delay_before_run_seconds: case.delay_before_run_seconds,
                run_command: None,
                build_duration_ms: build_output.duration.as_millis(),
                run_duration_ms: None,
                status,
                error: Some(command_failure_reason("build command", &build_output)),
                stdout: build_output.stdout_lossy(),
                stderr: build_output.stderr_lossy(),
                result: None,
            };
            write_case_artifacts(&case_dir, &report)?;
            return Ok(report);
        }
        let built_artifact = artifact_from_build_output(case, &build_output.stdout)?;
        let retained_artifact = case_dir.join(if profile.artifact_extension.is_empty() {
            "firmware".to_string()
        } else {
            format!("firmware.{}", profile.artifact_extension)
        });
        fs::copy(&built_artifact, &retained_artifact).map_err(|source| CampaignError::Io {
            path: retained_artifact.clone(),
            source,
        })?;
        let footprint = artifact_footprint(&built_artifact)?;
        let mut prepare_commands = Vec::new();
        for (index, prepare) in profile.prepare.iter().enumerate() {
            let spec = configured_runner_command(prepare, workspace, &built_artifact).silent(silent);
            prepare_commands.push(spec.display());
            let output = self.runner.run(&spec)?;
            write_bytes(
                &case_dir.join(format!("prepare-{index}-stdout.log")),
                &output.stdout,
            )?;
            write_bytes(
                &case_dir.join(format!("prepare-{index}-stderr.log")),
                &output.stderr,
            )?;
            if !output.success() {
                let report = CaseReport {
                    id: case.id.clone(),
                    name: case.name.clone(),
                    cargo_target: case.cargo_target.clone(),
                    environment,
                    features: case.features.clone(),
                    parameters: case.parameters.clone(),
                    artifact: Some(retained_artifact),
                    footprint,
                    baseline: case.baseline.clone(),
                    build_command: build_display,
                    prepare_commands,
                    delay_before_run_seconds: case.delay_before_run_seconds,
                    run_command: None,
                    build_duration_ms: build_output.duration.as_millis(),
                    run_duration_ms: None,
                    status: if output.timed_out {
                        CaseStatus::TimedOut
                    } else {
                        CaseStatus::RunFailed
                    },
                    error: Some(command_failure_reason("prepare command", &output)),
                    stdout: output.stdout_lossy(),
                    stderr: output.stderr_lossy(),
                    result: None,
                };
                write_case_artifacts(&case_dir, &report)?;
                return Ok(report);
            }
        }
        if let Some(seconds) = case.delay_before_run_seconds {
            std::thread::sleep(Duration::from_secs(seconds));
        }
        let run = runner_spec(profile, workspace, case, &built_artifact)?.silent(silent);
        let run_display = run.display();
        let run_output = self.runner.run(&run)?;
        write_run_logs(&case_dir, &run_output)?;
        let combined = run_output.combined_lossy();
        let parsed = parse(&combined).map(|mut result| {
            result.correlate_external(profile.require_external_measurements);
            enrich_result(&mut result, campaign_name, profile_name, case, &environment);
            result
        });
        let (status, error, result) = classify_run(profile, case, &run_output, parsed);
        if let Some(result) = &result {
            write_text(
                &case_dir.join("result.json"),
                &render_json(result)
                    .map_err(|error| CampaignError::InvalidConfig(error.to_string()))?,
            )?;
            write_text(&case_dir.join("report.md"), &render_markdown(result))?;
        }
        let report = CaseReport {
            id: case.id.clone(),
            name: case.name.clone(),
            cargo_target: case.cargo_target.clone(),
            environment,
            features: case.features.clone(),
            parameters: case.parameters.clone(),
            artifact: Some(retained_artifact),
            footprint,
            baseline: case.baseline.clone(),
            build_command: build_display,
            prepare_commands,
            delay_before_run_seconds: case.delay_before_run_seconds,
            run_command: Some(run_display),
            build_duration_ms: build_output.duration.as_millis(),
            run_duration_ms: Some(run_output.duration.as_millis()),
            status,
            error,
            stdout: if status != CaseStatus::Pass {
                run_output.stdout_lossy()
            } else {
                String::new()
            },
            stderr: if status != CaseStatus::Pass {
                run_output.stderr_lossy()
            } else {
                String::new()
            },
            result,
        };
        write_case_artifacts(&case_dir, &report)?;
        Ok(report)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "prepared execution carries explicit campaign, profile, artifact, and evidence inputs"
    )]
    fn run_prepared_case(
        &self,
        run_identity: (&str, &str),
        profile: &ResolvedRunnerProfile,
        workspace: &Path,
        campaign_dir: &Path,
        prepared: &PreparedCase,
        artifact: &Path,
        environment: ReproducibilityMetadata,
        silent: bool,
    ) -> Result<CaseReport, CampaignError> {
        let case = &prepared.case;
        let (campaign_name, profile_name) = run_identity;
        let case_dir = artifact_child(campaign_dir, &case.id, "expanded case id")?;
        if case_dir.exists() {
            fs::remove_dir_all(&case_dir).map_err(|source| CampaignError::Io {
                path: case_dir.clone(),
                source,
            })?;
        }
        fs::create_dir_all(&case_dir).map_err(|source| CampaignError::Io {
            path: case_dir.clone(),
            source,
        })?;
        let retained_artifact = case_dir.join(if profile.artifact_extension.is_empty() {
            "firmware".to_string()
        } else {
            format!("firmware.{}", profile.artifact_extension)
        });
        fs::copy(artifact, &retained_artifact).map_err(|source| CampaignError::Io {
            path: retained_artifact.clone(),
            source,
        })?;
        let mut prepare_commands = Vec::new();
        for (index, prepare) in profile.prepare.iter().enumerate() {
            let spec = configured_runner_command(prepare, workspace, artifact).silent(silent);
            prepare_commands.push(spec.display());
            let output = self.runner.run(&spec)?;
            write_bytes(
                &case_dir.join(format!("prepare-{index}-stdout.log")),
                &output.stdout,
            )?;
            write_bytes(
                &case_dir.join(format!("prepare-{index}-stderr.log")),
                &output.stderr,
            )?;
            if !output.success() {
                let report = CaseReport {
                    id: case.id.clone(),
                    name: case.name.clone(),
                    cargo_target: case.cargo_target.clone(),
                    environment,
                    features: case.features.clone(),
                    parameters: case.parameters.clone(),
                    artifact: Some(retained_artifact),
                    footprint: prepared.footprint,
                    baseline: case.baseline.clone(),
                    build_command: prepared.build_command.clone(),
                    prepare_commands,
                    delay_before_run_seconds: case.delay_before_run_seconds,
                    run_command: None,
                    build_duration_ms: prepared.build_duration_ms,
                    run_duration_ms: None,
                    status: if output.timed_out {
                        CaseStatus::TimedOut
                    } else {
                        CaseStatus::RunFailed
                    },
                    error: Some(command_failure_reason("prepare command", &output)),
                    stdout: output.stdout_lossy(),
                    stderr: output.stderr_lossy(),
                    result: None,
                };
                write_case_artifacts(&case_dir, &report)?;
                return Ok(report);
            }
        }
        if let Some(seconds) = case.delay_before_run_seconds {
            std::thread::sleep(Duration::from_secs(seconds));
        }
        let run = runner_spec(profile, workspace, case, artifact)?.silent(silent);
        let run_display = run.display();
        let run_output = self.runner.run(&run)?;
        write_run_logs(&case_dir, &run_output)?;
        let combined = run_output.combined_lossy();
        let parsed = parse(&combined).map(|mut result| {
            result.correlate_external(profile.require_external_measurements);
            enrich_result(
                &mut result,
                campaign_name,
                profile_name,
                case,
                &environment,
            );
            result
        });
        let (status, error, result) = classify_run(profile, case, &run_output, parsed);
        if let Some(result) = &result {
            write_text(
                &case_dir.join("result.json"),
                &render_json(result)
                    .map_err(|error| CampaignError::InvalidConfig(error.to_string()))?,
            )?;
            write_text(&case_dir.join("report.md"), &render_markdown(result))?;
        }
        let report = CaseReport {
            id: case.id.clone(),
            name: case.name.clone(),
            cargo_target: case.cargo_target.clone(),
            environment,
            features: case.features.clone(),
            parameters: case.parameters.clone(),
            artifact: Some(retained_artifact),
            footprint: prepared.footprint,
            baseline: case.baseline.clone(),
            build_command: prepared.build_command.clone(),
            prepare_commands,
            delay_before_run_seconds: case.delay_before_run_seconds,
            run_command: Some(run_display),
            build_duration_ms: prepared.build_duration_ms,
            run_duration_ms: Some(run_output.duration.as_millis()),
            status,
            error,
            stdout: if status != CaseStatus::Pass {
                run_output.stdout_lossy()
            } else {
                String::new()
            },
            stderr: if status != CaseStatus::Pass {
                run_output.stderr_lossy()
            } else {
                String::new()
            },
            result,
        };
        write_case_artifacts(&case_dir, &report)?;
        Ok(report)
    }

    fn collect_environment(
        &self,
        workspace: &Path,
        profile: &ResolvedRunnerProfile,
        silent: bool,
    ) -> ReproducibilityMetadata {
        let executable = profile
            .executable
            .as_deref()
            .unwrap_or(match profile.runner {
                RunnerKind::Simavr => "simavr",
                RunnerKind::Command => "unknown",
            });
        let mut controlled_environment = profile.controlled_environment.clone();
        if let Some(kernel) = command_value(workspace, "uname", &["-r"], silent) {
            controlled_environment
                .entry("host-kernel-release".to_string())
                .or_insert(kernel);
        }
        let mut environment = ReproducibilityMetadata {
            recorded_unix_seconds: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            source: SourceMetadata {
                workspace: workspace
                    .canonicalize()
                    .ok()
                    .map(|value| value.to_string_lossy().into_owned()),
                repository: command_value(workspace, "git", &["remote", "get-url", "origin"], silent),
                git_commit: command_value(workspace, "git", &["rev-parse", "HEAD"], silent),
                dirty: command_output(
                    workspace,
                    "git",
                    &["--no-optional-locks", "status", "--porcelain=v1"],
                    silent,
                )
                .map(|value| !value.is_empty()),
            },
            build: BuildMetadata {
                toolchain: profile.toolchain.clone(),
                rustc: command_value_with_toolchain(
                    workspace,
                    "rustc",
                    &["--version"],
                    profile.toolchain.as_deref(),
                    silent,
                ),
                cargo: command_value_with_toolchain(
                    workspace,
                    "cargo",
                    &["--version"],
                    profile.toolchain.as_deref(),
                    silent,
                ),
                target: Some(profile.target.clone()),
                optimization: Some(profile.cargo_profile.clone()),
                features: Vec::new(),
            },
            target: TargetMetadata {
                target: Some(profile.target.clone()),
                board: profile.board.clone(),
                mcu: profile.mcu.clone(),
                runner: Some(executable.to_string()),
                runner_version: command_value(workspace, executable, &["--version"], silent),
                transport: profile.transport.clone(),
                probe: profile.probe.clone(),
                clock_frequency_hz: profile.clock_frequency_hz,
                host_usb_path: profile.host_usb_path.clone(),
                venue: profile.venue.clone(),
                capabilities: profile.capabilities.clone(),
                resolved_bindings: profile.resolved_bindings.clone(),
                controlled_environment,
                configuration_identity: None,
            },
        };
        environment.target.configuration_identity = Some(format!(
            "{};rustc={};cargo={};runner-version={};controlled={:?}",
            profile.configuration_identity,
            environment.build.rustc.as_deref().unwrap_or("unknown"),
            environment.build.cargo.as_deref().unwrap_or("unknown"),
            environment
                .target
                .runner_version
                .as_deref()
                .unwrap_or("unknown"),
            environment.target.controlled_environment,
        ));
        environment
    }
}

fn enrich_result(
    result: &mut RunResult,
    campaign_name: &str,
    profile_name: &str,
    case: &ExpandedCase,
    environment: &ReproducibilityMetadata,
) {
    result.identity.campaign = Some(campaign_name.to_string());
    result.identity.case = Some(case.id.clone());
    result.identity.parameters = case.parameters.clone();
    result.identity.features = case.features.clone();
    result.identity.profile = Some(profile_name.to_string());
    let observed_frequency = result
        .starts
        .iter()
        .find_map(|value| value.frequency_hz)
        .or_else(|| {
            result
                .benchmarks
                .values()
                .flat_map(|value| &value.measurements)
                .find_map(|value| value.frequency_hz)
        });
    result.target = environment.target.clone();
    if result.target.clock_frequency_hz.is_none() {
        result.target.clock_frequency_hz = observed_frequency;
    }
    result.build = environment.build.clone();
    result.source = environment.source.clone();
}

fn selected_campaign(
    config: &ToolkitConfig,
    campaign_name: &str,
    selection: &CampaignSelection,
) -> Result<(CampaignConfig, Vec<ExpandedCase>), CampaignError> {
    let mut campaign = config
        .campaigns
        .get(campaign_name)
        .cloned()
        .ok_or_else(|| CampaignError::MissingCampaign(campaign_name.to_string()))?;
    if let Some(case_set) = &campaign.case_set {
        if !campaign.cases.is_empty() {
            return Err(CampaignError::InvalidConfig(format!(
                "campaign {campaign_name:?} cannot specify both cases and case-set"
            )));
        }
        campaign.cases = config.case_sets.get(case_set).cloned().ok_or_else(|| {
            CampaignError::InvalidConfig(format!("unknown case-set {case_set:?}"))
        })?;
    }
    if !config.profiles.contains_key(&campaign.profile) {
        return Err(CampaignError::MissingProfile(campaign.profile.clone()));
    }
    validate_cases(campaign_name, &campaign, &campaign.cases)?;
    validate_matrix_features(campaign_name, &campaign)?;
    if let Some(policy) = &campaign.constant_time {
        validate_constant_time_config(policy)?;
    }
    let cases = expand_cases(&campaign, selection)?;
    Ok((campaign, cases))
}

fn effective_constant_time(
    config: &ToolkitConfig,
    campaign: &CampaignConfig,
) -> Result<Option<ConstantTimeConfig>, CampaignError> {
    let mut visiting = Vec::new();
    let profile = config.inherited_profile(&campaign.profile, &mut visiting)?;
    Ok(campaign
        .constant_time
        .clone()
        .or(profile.constant_time))
}

fn safe_prepared_output(workspace: &Path, output: &Path) -> Result<PathBuf, CampaignError> {
    let workspace = workspace.canonicalize().map_err(|source| CampaignError::Io {
        path: workspace.to_path_buf(),
        source,
    })?;
    let output = normalized_absolute(output)?;
    reject_symlinked_output(&output)?;
    let resolved_output = output.canonicalize().unwrap_or_else(|_| output.clone());

    if workspace.starts_with(&resolved_output) {
        return Err(CampaignError::InvalidConfig(
            "prepared output must not be the workspace or one of its ancestors".to_string(),
        ));
    }
    let target = workspace.join("target");
    if resolved_output.starts_with(&workspace)
        && (!resolved_output.starts_with(&target) || resolved_output == target)
    {
        return Err(CampaignError::InvalidConfig(
            "prepared output inside the workspace must be a child of target/".to_string(),
        ));
    }
    Ok(output)
}

fn reject_symlinked_output(output: &Path) -> Result<(), CampaignError> {
    let mut current = PathBuf::new();
    for component in output.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(CampaignError::InvalidConfig(format!(
                    "prepared output path must not contain symlinks: {}",
                    current.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(CampaignError::Io {
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn reset_prepared_output(output: &Path) -> Result<(), CampaignError> {
    if !output.exists() {
        return Ok(());
    }
    let mut entries = fs::read_dir(output).map_err(|source| CampaignError::Io {
        path: output.to_path_buf(),
        source,
    })?;
    let empty = entries.next().is_none();
    let owned = fs::read_to_string(output.join(PREPARED_OUTPUT_MARKER))
        .is_ok_and(|value| value == "krabi-caliper\n")
        || read_prepared_campaign(&output.join("manifest.json")).is_ok();
    if !empty && !owned {
        return Err(CampaignError::InvalidConfig(format!(
            "refusing to replace non-empty, unowned prepared output {}",
            output.display()
        )));
    }
    fs::remove_dir_all(output).map_err(|source| CampaignError::Io {
        path: output.to_path_buf(),
        source,
    })
}

fn normalized_absolute(path: &Path) -> Result<PathBuf, CampaignError> {
    use std::path::Component;

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| CampaignError::Io {
                path: PathBuf::from("."),
                source,
            })?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
}

fn manifest_directory(manifest: &Path) -> &Path {
    match manifest.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

fn git_dirty_excluding(workspace: &Path, manifest: &Path, silent: bool) -> Option<bool> {
    let manifest = manifest.canonicalize().ok()?;
    let manifest_dir = manifest.parent()?;
    let workspace = workspace.canonicalize().ok()?;
    let excluded = if manifest_dir == workspace {
        manifest
    } else {
        manifest_dir.to_path_buf()
    };
    git_dirty_excluding_path(&workspace, &excluded, silent)
}

fn git_dirty_excluding_path(workspace: &Path, excluded: &Path, silent: bool) -> Option<bool> {
    let workspace = workspace.canonicalize().ok()?;
    let excluded = normalized_absolute(excluded).ok()?;
    let mut arguments = vec![
        "--no-optional-locks".to_string(),
        "status".to_string(),
        "--porcelain=v1".to_string(),
        "--".to_string(),
        ".".to_string(),
    ];
    if let Ok(relative) = excluded.strip_prefix(&workspace)
        && !relative.as_os_str().is_empty()
    {
        arguments.push(format!(":(exclude){}", relative.to_string_lossy()));
    }
    let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    command_output(&workspace, "git", &arguments, silent).map(|value| !value.is_empty())
}

fn command_value(workspace: &Path, program: &str, args: &[&str], silent: bool) -> Option<String> {
    let value = captured_command_output(workspace, program, args, None, silent)?;
    (!value.is_empty()).then_some(value)
}

fn host_target(workspace: &Path, toolchain: Option<&str>) -> Option<String> {
    captured_command_output(workspace, "rustc", &["-vV"], toolchain, true)?
        .lines()
        .find_map(|line| line.strip_prefix("host: ").map(ToString::to_string))
}

fn validate_prepared_build(
    prepared: &PreparedCampaign,
    profile: &ResolvedRunnerProfile,
) -> Result<(), CampaignError> {
    if prepared.build.target.as_deref() != Some(profile.target.as_str()) {
        return Err(CampaignError::InvalidConfig(
            "prepared build target does not match configuration".to_string(),
        ));
    }
    if prepared.build.optimization.as_deref() != Some(profile.cargo_profile.as_str()) {
        return Err(CampaignError::InvalidConfig(
            "prepared build profile does not match configuration".to_string(),
        ));
    }
    if prepared.build.toolchain != profile.toolchain {
        return Err(CampaignError::InvalidConfig(
            "prepared build toolchain does not match configuration".to_string(),
        ));
    }
    if prepared.constant_time != profile.constant_time {
        return Err(CampaignError::InvalidConfig(
            "prepared constant-time policy does not match configuration".to_string(),
        ));
    }
    Ok(())
}

fn command_value_with_toolchain(
    workspace: &Path,
    program: &str,
    args: &[&str],
    toolchain: Option<&str>,
    silent: bool,
) -> Option<String> {
    captured_command_output(workspace, program, args, toolchain, silent)
}

fn command_output(workspace: &Path, program: &str, args: &[&str], silent: bool) -> Option<String> {
    captured_command_output(workspace, program, args, None, silent)
}

fn captured_command_output(
    workspace: &Path,
    program: &str,
    args: &[&str],
    toolchain: Option<&str>,
    silent: bool,
) -> Option<String> {
    let mut spec = CommandSpec::new(program, workspace)
        .args(args.iter().copied())
        .timeout(Duration::from_secs(5))
        .silent(silent);
    if program == "git" {
        for key in ["GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE"] {
            spec = spec.env_remove(key);
        }
    }
    if let Some(toolchain) = toolchain {
        spec = spec.env("RUSTUP_TOOLCHAIN", toolchain);
    }
    let output = CommandRunner.run(&spec).ok()?;
    if !output.success() {
        return None;
    }
    let value = if output.stdout.is_empty() {
        output.stderr_lossy()
    } else {
        output.stdout_lossy()
    };
    Some(value.trim().to_string())
}

fn artifact_footprint(path: &Path) -> Result<Option<ElfFootprint>, CampaignError> {
    let mut header = [0_u8; 4];
    let mut file = fs::File::open(path).map_err(|source| CampaignError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.read_exact(&mut header)
        .map_err(|source| CampaignError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if header == *b"\x7fELF" {
        read_elf_footprint(path)
            .map(Some)
            .map_err(|error| CampaignError::InvalidConfig(error.to_string()))
    } else {
        Ok(None)
    }
}

pub fn expand_cases(
    campaign: &CampaignConfig,
    selection: &CampaignSelection,
) -> Result<Vec<ExpandedCase>, CampaignError> {
    let axes = campaign
        .matrix
        .iter()
        .map(|(name, values)| {
            let values = if selection.quick {
                values.first().into_iter().cloned().collect()
            } else {
                values.clone()
            };
            if values.is_empty() {
                Err(CampaignError::InvalidConfig(format!(
                    "matrix axis {name:?} has no values"
                )))
            } else {
                Ok((name.clone(), values))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let parameter_sets = cartesian(&axes);
    let mut expanded = Vec::new();
    for case in &campaign.cases {
        if !selection.cases.is_empty() && !selection.cases.contains(&case.name) {
            continue;
        }
        for parameters in &parameter_sets {
            let cargo_target = match (&case.example, &case.binary) {
                (Some(example), None) => CargoTarget::Example(example.clone()),
                (None, Some(binary)) => CargoTarget::Binary(binary.clone()),
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
            };
            let mut features = case.features.clone();
            features.extend(
                campaign
                    .matrix_features
                    .iter()
                    .map(|template| substitute(template, parameters)),
            );
            let suffix = parameters
                .iter()
                .map(|(key, value)| format!("{key}-{value}"))
                .collect::<Vec<_>>()
                .join("__");
            let id = if suffix.is_empty() {
                case.name.clone()
            } else {
                format!("{}__{}", case.name, suffix)
            };
            expanded.push(ExpandedCase {
                id,
                name: case.name.clone(),
                cargo_target,
                features,
                parameters: parameters.clone(),
                expected_benchmark: case.expected_benchmark.clone(),
                expected_suite: case.expected_suite.clone(),
                timeout_seconds: case.timeout_seconds,
                delay_before_run_seconds: case.delay_before_run_seconds,
                baseline: case
                    .baseline
                    .as_ref()
                    .or_else(|| {
                        campaign
                            .baseline_case
                            .as_ref()
                            .filter(|baseline| *baseline != &case.name)
                    })
                    .map(|baseline| {
                        if suffix.is_empty() {
                            baseline.clone()
                        } else {
                            format!("{baseline}__{suffix}")
                        }
                    }),
            });
        }
    }
    if expanded.is_empty() {
        return Err(CampaignError::InvalidConfig(
            "campaign selection produced no cases".to_string(),
        ));
    }
    Ok(expanded)
}

fn cargo_build_spec(
    profile: &ResolvedRunnerProfile,
    workspace: &Path,
    case: &ExpandedCase,
) -> CommandSpec {
    cargo_build_spec_fields(
        &profile.target,
        profile.toolchain.as_deref(),
        &profile.cargo_profile,
        profile.target_dir.as_deref(),
        workspace,
        case,
    )
}

fn prepared_cargo_build_spec(
    profile: &ResolvedBuildProfile,
    workspace: &Path,
    case: &ExpandedCase,
) -> CommandSpec {
    cargo_build_spec_fields(
        &profile.target,
        profile.toolchain.as_deref(),
        &profile.cargo_profile,
        profile.target_dir.as_deref(),
        workspace,
        case,
    )
}

fn cargo_build_spec_fields(
    target: &str,
    toolchain: Option<&str>,
    cargo_profile: &str,
    target_dir: Option<&Path>,
    workspace: &Path,
    case: &ExpandedCase,
) -> CommandSpec {
    let mut args = vec![
        OsString::from("build"),
        OsString::from("--profile"),
        OsString::from(cargo_profile),
        OsString::from("--target"),
        OsString::from(target),
        OsString::from("--no-default-features"),
        OsString::from("--message-format=json-render-diagnostics"),
    ];
    if !case.features.is_empty() {
        args.push(OsString::from("--features"));
        args.push(OsString::from(case.features.join(",")));
    }
    args.push(OsString::from(case.cargo_target.cargo_flag()));
    args.push(OsString::from(case.cargo_target.name()));
    let mut spec = CommandSpec::new("cargo", workspace)
        .args(args)
        .timeout(Duration::from_secs(600));
    if let Some(toolchain) = toolchain {
        spec = spec.env("RUSTUP_TOOLCHAIN", toolchain);
    }
    if let Some(target_dir) = target_dir {
        spec = spec.env("CARGO_TARGET_DIR", workspace.join(target_dir));
    }
    spec
}

fn runner_spec(
    profile: &ResolvedRunnerProfile,
    workspace: &Path,
    case: &ExpandedCase,
    artifact: &Path,
) -> Result<CommandSpec, CampaignError> {
    let timeout = Duration::from_secs(case.timeout_seconds.unwrap_or(profile.timeout_seconds));
    let spec: Result<CommandSpec, CampaignError> = match profile.runner {
        RunnerKind::Simavr => {
            #[cfg(not(target_os = "windows"))]
            {
                Ok(
                    CommandSpec::new(profile.executable.as_deref().unwrap_or("simavr"), workspace)
                        .args(profile.args.iter())
                        .arg(artifact)
                        .timeout(timeout),
                )
            }
            #[cfg(target_os = "windows")]
            {
                const SCRIPT: &str = concat!(
                    "deadline=$1; executable=$2; ",
                    "artifact=$(wslpath -u \"$3\") || exit 1; ",
                    "shift 3; exec timeout \"$deadline\" \"$executable\" \"$@\" \"$artifact\""
                );
                let executable = profile.executable.as_deref().unwrap_or("simavr");
                Ok(CommandSpec::new("wsl", workspace)
                    .args(["-e", "bash", "-lc", SCRIPT, "krabi-caliper"])
                    .arg(timeout.as_secs().to_string())
                    .arg(executable)
                    .arg(artifact)
                    .args(profile.args.iter())
                    .timeout(timeout + Duration::from_secs(2)))
            }
        }
        RunnerKind::Command => {
            let executable = profile.executable.as_ref().ok_or_else(|| {
                CampaignError::InvalidConfig("command runner requires executable".to_string())
            })?;
            Ok(CommandSpec::new(executable, workspace)
                .args(
                    profile
                        .args
                        .iter()
                        .map(|value| value.replace("{artifact}", &artifact.to_string_lossy())),
                )
                .timeout(timeout))
        }
    };
    let spec = spec?;
    Ok(if let Some(marker) = &profile.completion_marker {
        spec.completion_marker(marker.as_bytes().to_vec())
            .completion_action(profile.completion_action)
    } else {
        spec
    })
}

fn configured_runner_command(
    command: &RunnerCommandConfig,
    workspace: &Path,
    artifact: &Path,
) -> CommandSpec {
    CommandSpec::new(&command.executable, workspace)
        .args(
            command
                .args
                .iter()
                .map(|value| value.replace("{artifact}", &artifact.to_string_lossy())),
        )
        .timeout(Duration::from_secs(command.timeout_seconds))
}

fn artifact_from_build_output(
    case: &ExpandedCase,
    stdout: &[u8],
) -> Result<PathBuf, CampaignError> {
    let mut artifacts = Message::parse_stream(Cursor::new(stdout))
        .filter_map(Result::ok)
        .filter_map(|message| match message {
            Message::CompilerArtifact(artifact)
                if artifact.target.name == case.cargo_target.name() =>
            {
                artifact.executable.map(|path| path.into_std_path_buf())
            }
            _ => None,
        });
    let artifact = artifacts.next().ok_or_else(|| {
        CampaignError::InvalidConfig(format!(
            "cargo did not report an executable artifact for {} {:?}",
            case.cargo_target.cargo_flag(),
            case.cargo_target.name()
        ))
    })?;
    if artifacts.next().is_some() {
        return Err(CampaignError::InvalidConfig(format!(
            "cargo reported multiple executable artifacts for {} {:?}",
            case.cargo_target.cargo_flag(),
            case.cargo_target.name()
        )));
    }
    if !artifact.is_file() {
        return Err(CampaignError::InvalidConfig(format!(
            "cargo reported artifact {}, but it is missing",
            artifact.display()
        )));
    }
    Ok(artifact)
}

fn classify_run(
    profile: &ResolvedRunnerProfile,
    case: &ExpandedCase,
    output: &CommandOutput,
    parsed: Result<RunResult, super::ParseError>,
) -> (CaseStatus, Option<String>, Option<RunResult>) {
    if output.timed_out {
        return (
            CaseStatus::TimedOut,
            Some(command_failure_reason("runner command", output)),
            parsed.ok(),
        );
    }
    if !output.success() {
        return (
            CaseStatus::RunFailed,
            Some(command_failure_reason("runner command", output)),
            parsed.ok(),
        );
    }
    let mut result = match parsed {
        Ok(result) => result,
        Err(error) => return (CaseStatus::ProtocolError, Some(error.to_string()), None),
    };
    if case.expected_benchmark.is_none()
        && case.expected_suite.is_none()
        && result.outcomes.is_empty()
    {
        return (
            CaseStatus::MissingTerminalRecord,
            Some("no EM_OUTCOME record was emitted".to_string()),
            Some(result),
        );
    }
    if let Some(expected) = &case.expected_benchmark
        && !result
            .outcomes
            .iter()
            .any(|value| &value.benchmark == expected)
    {
        return (
            CaseStatus::MissingTerminalRecord,
            Some(format!("no EM_OUTCOME record for {expected:?}")),
            Some(result),
        );
    }
    if let Some(expected) = &case.expected_suite
        && !result
            .summaries
            .iter()
            .any(|value| &value.suite == expected)
    {
        return (
            CaseStatus::MissingTerminalRecord,
            Some(format!("no EM_SUMMARY record for {expected:?}")),
            Some(result),
        );
    }
    let constant_time_error = profile
        .constant_time
        .as_ref()
        .and_then(|policy| apply_constant_time_policy(&mut result, policy));
    let status = match result.status {
        RunStatus::Pass => CaseStatus::Pass,
        RunStatus::Fail => CaseStatus::WorkloadFail,
        RunStatus::MeasurementError => CaseStatus::MeasurementError,
        RunStatus::Informational => CaseStatus::MissingTerminalRecord,
    };
    (status, constant_time_error, Some(result))
}

fn apply_constant_time_policy(
    result: &mut RunResult,
    policy: &ConstantTimeConfig,
) -> Option<String> {
    result.welch_analyses = super::analyze_welch(result, policy.welch_threshold);
    if !policy.gate {
        return None;
    }
    let protected = result
        .welch_analyses
        .iter()
        .filter(|analysis| policy.protected_classes.contains(&analysis.class))
        .collect::<Vec<_>>();
    let controls = result
        .welch_analyses
        .iter()
        .filter(|analysis| policy.control_classes.contains(&analysis.class))
        .collect::<Vec<_>>();
    if protected.is_empty() {
        result.status = RunStatus::Fail;
        return Some("constant-time gate found no analyzable protected-class samples".to_string());
    }
    let insufficient = protected.iter().chain(&controls).any(|analysis| {
        analysis.a_samples < policy.minimum_samples_per_class
            || analysis.b_samples < policy.minimum_samples_per_class
    });
    let leak = protected
        .iter()
        .any(|analysis| analysis.exceeds_threshold());
    let missed_control = !policy.control_classes.is_empty()
        && (controls.is_empty()
            || controls
                .iter()
                .any(|analysis| !analysis.exceeds_threshold()));
    if insufficient || leak || missed_control {
        result.status = RunStatus::Fail;
    }
    if insufficient {
        Some(format!(
            "constant-time gate requires at least {} samples per class",
            policy.minimum_samples_per_class
        ))
    } else if leak {
        Some(format!(
            "constant-time gate exceeded Welch threshold |t| > {}",
            policy.welch_threshold
        ))
    } else if missed_control {
        Some("constant-time gate did not detect the configured positive control".to_string())
    } else {
        None
    }
}

fn cartesian(axes: &[(String, Vec<String>)]) -> Vec<BTreeMap<String, String>> {
    let mut sets = vec![BTreeMap::new()];
    for (name, values) in axes {
        let mut next = Vec::new();
        for set in &sets {
            for value in values {
                let mut set = set.clone();
                set.insert(name.clone(), value.clone());
                next.push(set);
            }
        }
        sets = next;
    }
    sets
}

fn substitute(template: &str, parameters: &BTreeMap<String, String>) -> String {
    parameters
        .iter()
        .fold(template.to_string(), |value, (key, replacement)| {
            value.replace(&format!("{{{key}}}"), replacement)
        })
}

fn write_run_logs(path: &Path, output: &CommandOutput) -> Result<(), CampaignError> {
    write_bytes(&path.join("raw-stdout.log"), &output.stdout)?;
    write_bytes(&path.join("raw-stderr.log"), &output.stderr)
}

fn write_case_metadata(path: &Path, report: &CaseReport) -> Result<(), CampaignError> {
    write_text(
        &path.join("metadata.json"),
        &serde_json::to_string_pretty(report).map_err(CampaignError::Json)?,
    )
}

fn write_case_artifacts(path: &Path, report: &CaseReport) -> Result<(), CampaignError> {
    write_case_metadata(path, report)?;
    if report.status != CaseStatus::Pass {
        write_text(&path.join("report.md"), &report.render_failure_markdown())?;
    }
    Ok(())
}

fn command_failure_reason(phase: &str, output: &CommandOutput) -> String {
    if output.timed_out {
        format!(
            "{phase} timed out after {:.1} seconds",
            output.duration.as_secs_f64()
        )
    } else {
        format!("{phase} exited with {}", display_exit_status(output.status))
    }
}

fn display_exit_status(status: Option<std::process::ExitStatus>) -> String {
    match status.and_then(|status| status.code()) {
        Some(code) => format!("status {code}"),
        None => status.map_or_else(|| "no exit status".to_string(), |status| status.to_string()),
    }
}

fn artifact_child(root: &Path, component: &str, kind: &str) -> Result<PathBuf, CampaignError> {
    validate_artifact_component(kind, component)?;
    Ok(root.join(component))
}

fn write_campaign_artifacts(path: &Path, report: &CampaignReport) -> Result<(), CampaignError> {
    fs::create_dir_all(path).map_err(|source| CampaignError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    write_text(&path.join("report.md"), &report.render_markdown())?;
    write_text(&path.join("report.csv"), &report.render_csv())?;
    write_text(
        &path.join("results.json"),
        &serde_json::to_string_pretty(report).map_err(CampaignError::Json)?,
    )
}

fn write_bytes(path: &Path, value: &[u8]) -> Result<(), CampaignError> {
    fs::write(path, value).map_err(|source| CampaignError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn write_text(path: &Path, value: &str) -> Result<(), CampaignError> {
    write_bytes(path, value.as_bytes())
}

fn unit_name(unit: super::OwnedUnit) -> &'static str {
    match unit {
        super::OwnedUnit::CoreCycles => "cycles",
        super::OwnedUnit::TimerTicks => "timer ticks",
        super::OwnedUnit::Instructions => "instructions",
        super::OwnedUnit::SimulatorCycles => "simulator cycles",
    }
}
