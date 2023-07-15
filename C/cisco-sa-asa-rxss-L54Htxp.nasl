#TRUSTED 7670e4b71681295640f4a9d283eef36356bf769e59d5d5fd6778002cf44f1b2f0423af5a7d1c8cf2877bf8b63ff7e5d08b61cdf583809ba1dbf57a2a69c5abd88d5205fe48d84717bb735a2b5aeb241dd93a3fa6ab3aea99ab293d15daeab83a236681c22a1b7901207466a4359309ba0023ee4880502ea9a5c9df964a195f21ab7a37a60c1a75536ad06db7ac5319a9e4f5552e70d3d7724aeb1e0af4f39f1542013a78bc07356f56c19fc67948c113afd167c39006cd78e216845a1f3874ca00589be75f6376a7e20cad198913d6c016c8421330108a67f2a0f6449232ae9a391a8988763439ed61b6f91dbfce440795127dd4261b2eec9d8d9ed05b6d6182bddd95366a38dbe8fb166407b1e9326eae82869ca37b12a7b22b4747f145521ee6f55163ce348b111e52bba6a3ecc44e7377dc4057d494034104a4e5eca505d0154042012c8574240f5a75be9fbcc6a624e91dc2b87e4c3438387dc58ea4f3267ff5a9870c983d99b14bfe3701164229232ab433a4a9e02ec416599a53dad8b99bec8f43a8d125a6c5cef0c9419e733effcb92607943e23c105454d6cc4e9be066445a797da3e781def21d2f60527c8c008b0ce62b47ff3e8316fd2410a594aace8bdf122c6f769dae96abaf9322a5fc2918e0683e70ced4dbd346c5bd6aaf6e4936a6bc1d69f96b13efc87521c817986fe33e79fefd5874ffc8684228b2f133
#TRUST-RSA-SHA256 a4501e3dcbb8575dccb31e161389068e3f60341a9bcfdd1e5776c6e52575f40dd04a3e9d853f7d834fa1b7e8b3b28b8ae48a8e0e9b346f369420b60d049aca46912266ad0f5e3ddda4d11ee780ca3c719bb712cebbd962b1856d9ec8031336c9a5808f8c1c41c87d2eab6474d718eabe5982e7530dc279be828efe800984e901512d5ab69969049cbe8bd87e18162657d304a3bbb0f4a0579752120cb60d2c597812435c259bb68dcaac62ad6a180f9f5b82d41a61be1fec6f580ecb94b5aedae49487f201466f07dec6c78abc2986930c5930801b2419fbf04727a34e50bb6b6606c02b0727ccd1c89f64b857d7e06720094655753b8d1e9da912b2d2bd4a4e7cfbddea3d9176e720a40ba6c9a4d7d88f20097e01b34632d2c0d139e1d32ea7407b4c64a7a0f2668ba5e00f3e59b4d15ae8539aafa67a68d58b2a4b81fc6f76efad24aa393170a5ea3b286beece819940fd5e108c375c5819804361b958a32c15e8c062d346bbab9d0027af6257547196357c31b6d14e18358c6792ec8290124fb55d5c8717a5a3338662916d29c08e7da037781e38db485f2e2a60d644b5d08fd9b1d8d7bbe48eec06c84b1e25118b1f954f36d62e30f2ad15e288a23b22810ed03f0f30e784c4ab7c816bd046b20eb6ffe4a77411562c46900b8e08707a2489c3844df9c3069d7bb95e7f3143af450bdae5510044c0014684e2474cfaa8b9
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149877);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3599");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv33712");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-rxss-L54Htxp");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Adaptive Security Appliance Software Web-Based Management Interface Reflected XSS (cisco-sa-asa-rxss-L54Htxp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by a vulnerability in the web-based management
interface that could allow an unauthenticated, remote attacker to conduct a cross-site scripting (XSS) attack against a
user of the interface. This vulnerability exists because the web-based management interface does not properly validate
user-supplied input. An attacker could exploit this vulnerability by persuading a user of the interface to click a
crafted link. A successful exploit could allow the attacker to execute arbitrary script code in the context of the
interface or access sensitive, browser-based information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-rxss-L54Htxp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5d0d36a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv33712");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv33712");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3599");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '9.6.4.45'},
  {'min_ver': '9.7', 'fix_ver': '9.8.4.29'},
  {'min_ver': '9.9', 'fix_ver': '9.9.2.80'},
  {'min_ver': '9.10', 'fix_ver': '9.10.1.43'},
  {'min_ver': '9.12', 'fix_ver': '9.12.4.4'},
  {'min_ver': '9.13', 'fix_ver': '9.13.1.13'},
  {'min_ver': '9.14', 'fix_ver': '9.14.1.29'}
];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ASA_HTTP_Server'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv33712',
  'cmds'     , make_list('show running-config'),
  'xss'      , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
