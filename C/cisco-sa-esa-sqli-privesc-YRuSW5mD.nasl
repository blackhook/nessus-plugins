#TRUSTED 7226d056001b68f064772f383af6157f4633a610bed1a0ed3646c32f660f406b345d1b6dbc699371b27d7018918bb41175ace955ff408ac70041af83a2ab0a8035c6dd18f07a4dbc826d3ceb5e93aa5fd30a295def2481a0f8ec7d90d232a5f2614bd73e879426927f1151c7982a15a3d9f2e7cba62757fc494dfaf8d0dcca8687a9f6158b1cf51cc9e2299da46455ad8e2b2c6ac02ea11eb5f3464e8a739ef84c65c33a26eae5ab922c787b16c229a6561b3053c2d2180f6a6702b6f06f314a8f98b80b4138a666fa3f051706154c1fa629eea7efdb353cf9fe40d3067ac83f7232e79df2c3c7903bfbe52bbaf4fdc1a718145126301e70acf761fba2cf844ededa51ad0a24c77b80dd9a4e118852cf08e78faa5c7fc0a228dc0fcaee05046d20d58fd8d86c02db0fb3afe796f7f51d89e57518ada38bfe2582dd9c6bfaea05c5a34d9f3578b4b5690ac41bf7d2e45fc51b224399552b1ea49e018ac100ef482f0f03444b9171ffd637fc0e3d943b5b0b44d5bcee38af04dd1447b1f18336919442f0b2f454152425528a3c44051f8b0a53887fe5333241e4b0559db42c36298eeb9027a8ac61eb8936735b714dd83b4b563a5eb5ac3ac9e9ea0057dfd3a406269b16b9ca1c6fb9dd3ae4aeaf9b3e821db5e053c9c3dfcd1fa5793b49fce335fe4b9affe7394e429d6fb42facc6976c57050984b501fdc9ece0d41649d11910
#TRUST-RSA-SHA256 9fea302431c1c314b1c2f3a444f6c6c0c9e51dc3170fc1c031f110122e12c465bdfabba775dff4c14ab622d29a4c9e084505b9f26ffb7e0bad8cda8dfec319bb942b9ef94d0226c080de8cf3d62a6f14d2f9bcbab65eafe108af57ce6cdea1b08d2faa39e59719a0fa6a6963f76ea388e3cb80d49f0f9c6ee835637ea819bedd7165cedb12d2325e8a34b90ac0a04f7b11e1de6a77b7976db39f34151c09e92efbdd60adff84a6fc297d6032244ae95db105e7a5333ba822460ead78600ac0d12cef7ad036b2be29b5a44d94fada229a486fa9baba00a6ed0a9edd2bb0cba79315816f904a34acc54673d56ee2b828d539b0b2dd8e7b35a7a3dd4df6de53d7ebca8b366c1b2c9cb65ef7bdd5edb0ca3ee0eef618a133ec042390e5f7a389d00b1e0e57b3dd679decf9b7b8acfcd712b6fb59eb7a5be1d9e59667b4125bb5c3b230b5b30cbe28562ad2d9f6b51633420f48c0ebf4316e8de4fda5cc5e7d3c27cdcdd33c3a1cb29b54d7810460993de12780898db59c13ac7322bc3af62f3a96fe3241203b4e41c9584008223e01f555ebdaedc65b4331ba5ca32eddff6069b120e453670c4f3da68106a2fbec3835afc79df650b6250d9999c7d39eb71fab340f1d0dbcf280623a368fb3162aad088baa51c8660c4403e76d6a066d25b6754da330d17edd5d9e628cc0ce43415c49c65a4844c327d47dc929b53f3396da2c7472
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166911);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id("CVE-2022-20867", "CVE-2022-20868");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc12181");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc12183");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esasmawsa-vulns-YRuSW5mD");
  script_xref(name:"IAVA", value:"2022-A-0463");

  script_name(english:"Cisco Email Security Appliance Multiple Vulnerabilities (cisco-sa-esasmawsa-vulns-YRuSW5mD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance is affected by multiple vulnerabilities. 

  - an SQL injection vulnerability that could allow an authenticated, remote attacker to conduct SQL injection attacks 
    as root on an affected system. To exploit this vulnerability, an attacker would need to have the credentials of a 
    high-privileged user account. (CVE-2022-20867)

  - a privilege escalation vulnerability that could allow an authenticated, remote attacker to elevate privileges 
    on an affected system. This vulnerability is due to the use of a hard-coded value to encrypt a token that is used 
    for certain API calls. An attacker could exploit this vulnerability by authenticating to an affected device and 
    sending a crafted HTTP request. (CVE-2022-20868)  

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esasmawsa-vulns-YRuSW5mD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38dfc160");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc12181");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwc12181 and CSCwc12183");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20868");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

var vuln_ranges = [
  {'min_ver' : '13.0', 'fix_ver' : '14.2.1.015'},
  {'min_ver' : '14.3', 'fix_ver' : '14.3.0.0201'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'flags'         , {'sqli':TRUE},
  'bug_id'        , 'CSCwc12181, CSCwc12183',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
