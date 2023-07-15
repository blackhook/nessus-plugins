#TRUSTED 613ae06924956f668f671d375839c7a8c5725084265686c1abd98d39e844e1037765e377c60459b681c92e8b9e646f6475a7cd5e01710608b4ff375835e109fed1d7245e7f7583cf8205f5566b55913d165fc64d6ce079948a6d84d945d726ce7b095d496b7ec9a024925d5413261ddd2dd778da5b0b57f1a2d0206a0f08ac61821742b4fcaa4c376770ccb1736d45a1d5aebfe9b269b90b96f104533dff830f04b57abc524b845e22ff5bab000ffffd354d7c824235351f77c2a3f6ad3e1574270790dbd6736755a8e82641dd2c50d90a47a0e644c867e16f2cf58ab70289a106d51ff40767b1c6176241ddee96a5ab05691c2dae7979a79f1eec2b6b52e4ff910c3b2a1dea29c3bf77d5ee571aed7029702f9c1c608bcc9b584110dfff1fb83f7ed886dcedbb73b7be17fb66af832f44477815a5547004d986badb98c9e99210ca7707993ccfe9ea641839dc3b7ad517f8d82b3f28767404b912121fa779d5b3571347daed6d9290b500f2a18c90aea104f9473e2dc5e66ab9d50ecfbb0ee17f05d3d4929958034ba1915e254b146d492506cffe0cc8a5097e2c195e22134b49fc6f04ef1d4e1693f15e8ce3673c50ce39c9baff6267cd427055e4a5cca77b1a0349ac96d4a226a302b26d87d604325499128c004e64793405cce3b0dcdf9736a491fb7c2ca789dd8072e05c698f3a005efa7931b2cc13f9a72572e4aaae35
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134383);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/13");

  script_cve_id("CVE-2019-12696", "CVE-2019-12697");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo70545");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp66222");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-firepwr-bypass");
  script_xref(name:"IAVA", value:"2019-A-0370");

  script_name(english:"Cisco Firepower System Software Detection Engine RTF and RAR Malware and File Policy Bypass Vulnerabilities (cisco-sa-20191002-firepwr-bypass)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower System Software is affected by two vulnerabilities in the
detection engine, as follows:

  - A vulnerability due to incorrect detection of the RTF file syntax. An unauthenticated, remote attacker can
    exploit this, by sending a malicious RTF file, in order to bypass a configured Malware and File Policy for
    an RTF file type. (CVE-2019-12697)

  - A vulnerability due to incorrect detection of the RAR file syntax. An unauthenticated, remote attacker can
    exploit this, by sending a malicious RTF file, in order to bypass a configured Malware and File Policy for
    a RAR file type. (CVE-2019-12696)


Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-firepwr-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f4cea308");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo70545");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp66222");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvo70545, CSCvp66222");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12697");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(693);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_asa_firepower_version.nasl", "cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');
product_info['model'] = product_info['Model'];
model = toupper(product_info['model']);

if (!(empty_or_null(model)) && # NGIPS
    model !~ "^(21|41|10|70|80|93|30)[0-9]{2}" && # Firepower and ISA
    model !~ "^ISR" && # ISR
    model !~ "^55[0-9]{2}-X" && # 5500-X
    'FTDV' >!< model # FTDv
   )
  audit(AUDIT_HOST_NOT, 'an affected model');


vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '6.2.3.15'},
  {'min_ver' : '6.3.0',  'fix_ver' : '6.3.0.5'},
  {'min_ver' : '6.4.0',  'fix_ver' : '6.4.0.6'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo70545, CSCvp66222'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
