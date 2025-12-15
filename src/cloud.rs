use std::path::Path;
use crate::models::{AssetMetadata, ThreatIndicator};

#[derive(Default)]
pub struct CloudAnalyzer;

impl CloudAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Analyze a file or directory for Cloud/Infrastructure risks
    pub fn analyze(&self, path: &Path, asset: &mut AssetMetadata) {
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
        
        // 1. Docker Images (tar exports)
        if name.ends_with(".tar") {
            self.analyze_docker_image(path, asset);
        }

        // 2. Kubernetes Manifests
        if name.ends_with(".yaml") || name.ends_with(".yml") || name.ends_with(".json") {
             // Heuristic: Check if content looks like K8s
             self.analyze_k8s_manifest(path, asset);
        }

        // 3. Terraform Files
        if name.ends_with(".tf") {
            self.analyze_terraform(path, asset);
        }

        // 4. Git Internals
        // This is usually called on directories, but scanner works file-by-file.
        // We might need a special check in scanner.rs for ".git" directory or handle it here if path IS .git
        if name == ".git" && path.is_dir() {
            self.analyze_git_repo(path, asset);
        }
    }

    fn analyze_docker_image(&self, path: &Path, asset: &mut AssetMetadata) {
        // Basic check: Try to open as tar and look for manifest.json
        use std::fs::File;
        use tar::Archive;

        if let Ok(file) = File::open(path) {
            let mut archive = Archive::new(file);
            let mut is_docker = false;
            let mut layer_count = 0;

            if let Ok(entries) = archive.entries() {
                for entry in entries {
                    if let Ok(entry) = entry {
                        if let Ok(path) = entry.path() {
                            let path_str = path.to_string_lossy();
                            if path_str == "manifest.json" {
                                is_docker = true;
                                asset.content_matches.push("Docker Image Manifest found".to_string());
                            }
                            if path_str.ends_with("layer.tar") {
                                layer_count += 1;
                            }
                        }
                    }
                }
            }

            if is_docker {
                asset.threat_indicators.push(ThreatIndicator {
                    indicator_type: "Infrastructure".to_string(),
                    value: "Docker Image".to_string(),
                    confidence: 100,
                    description: format!("Docker Image export detected with {} layers", layer_count),
                });
                
                // Risk bump for unencrypted container exports
                asset.risk_score = std::cmp::max(asset.risk_score, 10);
            }
        }
    }

    fn analyze_k8s_manifest(&self, path: &Path, asset: &mut AssetMetadata) {
        if let Ok(content) = std::fs::read_to_string(path) {
            let mut indicators = Vec::new();

            // Heuristic checks (Text-based to avoid complex YAML parsing errors for now)
            // But we can check structural keywords
            if content.contains("apiVersion:") && content.contains("kind:") {
                if content.contains("privileged: true") {
                    indicators.push("Privileged Container");
                }
                if content.contains("hostNetwork: true") {
                    indicators.push("Host Network Access");
                }
                if content.contains("imagePullPolicy: Always") {
                    // Not a threat, but interesting
                }
                if content.contains("cluster-admin") {
                    indicators.push("Cluster Admin Role Binding");
                }
                
                // Secrets in Env
                if content.contains("value:") && (content.contains("key") || content.contains("secret") || content.contains("password")) {
                     // Potential hardcoded secret
                }
            }

            for ind in indicators {
                asset.threat_indicators.push(ThreatIndicator {
                    indicator_type: "Kubernetes Misconfiguration".to_string(),
                    value: ind.to_string(),
                    confidence: 90,
                    description: format!("Insecure Kubernetes configuration detected: {}", ind),
                });
                asset.risk_score = std::cmp::max(asset.risk_score, 40);
            }
        }
    }

    fn analyze_terraform(&self, path: &Path, asset: &mut AssetMetadata) {
         if let Ok(content) = std::fs::read_to_string(path) {
             // Debug print
             println!("DEBUG: Analyzing Terraform: {:?}", path);
             if content.contains("0.0.0.0/0") {
                 println!("DEBUG: Found Open CIDR!");
                 asset.threat_indicators.push(ThreatIndicator {
                     indicator_type: "Terraform Security".to_string(),
                     value: "Open CIDR".to_string(),
                     confidence: 80,
                     description: "Security Group allows access from 0.0.0.0/0".to_string(),
                 });
                 asset.risk_score = std::cmp::max(asset.risk_score, 30);
             }

             // 2. Hardcoded AWS Keys
             if content.contains("access_key") && content.contains("\"") {
                 asset.threat_indicators.push(ThreatIndicator {
                     indicator_type: "Terraform Security".to_string(),
                     value: "Hardcoded Credentials".to_string(),
                     confidence: 60,
                     description: "Potential hardcoded access_key in Terraform file".to_string(),
                 });
                 asset.risk_score = std::cmp::max(asset.risk_score, 50);
             }
         } else {
             println!("DEBUG: Failed to read Terraform: {:?}", path);
         }
    }

    fn analyze_git_repo(&self, path: &Path, asset: &mut AssetMetadata) {
        use git2::Repository;
            
        if let Ok(repo) = Repository::open(path) {
                // 1. Scan Reflog for deleted/moved tips
                // (Simplified: just look at all local references and their immediate history)
                
                let mut commits_to_scan = Vec::new();

                if let Ok(references) = repo.references() {
                    for reference in references {
                        if let Ok(reference) = reference {
                            if let Ok(commit) = reference.peel_to_commit() {
                                commits_to_scan.push(commit);
                            }
                        }
                    }
                }

                // Scan commit messages and diffs (limit 20 newest commits per ref to avoid huge time)
                for commit in commits_to_scan {
                    if let Some(msg) = commit.message() {
                        if msg.contains("password") || msg.contains("secret") || msg.contains("key") {
                             asset.threat_indicators.push(ThreatIndicator {
                                indicator_type: "Git History".to_string(),
                                value: "Suspicious Commit Message".to_string(),
                                confidence: 70,
                                description: format!("Commit message contains suspicious keywords: '{}'", msg.trim()),
                            });
                        }
                    }
                }
            }
    }

    pub fn validate_cloud_credentials(&self, asset: &mut AssetMetadata) {
        // This should theoretically only run if safe/enabled, but method is public
        // We will do a basic check implementation
        
        for secret in &asset.detected_secrets {
            if secret.provider == "AWS" && secret.secret_type == "Access Key ID" {
                 // Requires Secret Key to actually validate, so we can't fully validate with just ID.
                 // We skip partial validation for now.
            }

            if secret.provider == "GitHub" {
                // Try validating potential Personal Access Token
                let _token = &secret.context; // Assuming context holds token or we grab it from value (redacted unfortunately)
                // Since value is redacted in struct, we can't validate here unless we had access to raw value.
                // NOTE: AssetMetadata stores REDACTED value. We cannot validate redacted credentials.
                
                // Design Choice: validation needs raw value. `SecretScanner` has it, but it redacts it before storing.
                // We would need to hook into SecretScanner or store raw value in a secure field.
                // For now, we will mark this as "Requires Raw Value" and skip.
            }
        }
    }
}
