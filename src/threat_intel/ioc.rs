//! IoC Database and Attribution

use std::collections::HashMap;

/// IoC data container
pub struct IocData {
    pub malware_hashes: HashMap<String, String>,
    pub malicious_domains: Vec<String>,
    pub malicious_ips: Vec<String>,
    pub attribution_map: HashMap<String, String>,
    pub cve_map: HashMap<String, String>,
}

/// Load IoC database
pub fn load_ioc_database() -> IocData {
    let mut malware_hashes = HashMap::new();
    malware_hashes.insert(
        "44d88612fea8a8f36de82e1278abb02f".to_string(),
        "EICAR Test File".to_string(),
    );

    let malicious_domains = vec![
        "evil.com".to_string(),
        "malware.ru".to_string(),
        "badsite.cn".to_string(),
    ];

    let malicious_ips = vec![
        "1.2.3.4".to_string(),
        "5.6.7.8".to_string(),
    ];

    let mut attribution_map = HashMap::new();
    attribution_map.insert("APT28_Loader".to_string(), "APT28 (Fancy Bear)".to_string());
    attribution_map.insert("Lazarus_Kratraf".to_string(), "Lazarus Group".to_string());
    attribution_map.insert("CobaltStrike_Beacon".to_string(), "Cobalt Strike".to_string());
    attribution_map.insert("Mimikatz_Memory".to_string(), "Mimikatz Tool".to_string());

    let mut cve_map = HashMap::new();
    cve_map.insert("log4j".to_string(), "CVE-2021-44228".to_string());
    cve_map.insert("printnightmare".to_string(), "CVE-2021-34527".to_string());
    cve_map.insert("zerologon".to_string(), "CVE-2020-1472".to_string());
    cve_map.insert("proxyshell".to_string(), "CVE-2021-34473".to_string());
    cve_map.insert("struts2".to_string(), "CVE-2017-5638".to_string());

    IocData {
        malware_hashes,
        malicious_domains,
        malicious_ips,
        attribution_map,
        cve_map,
    }
}
