#TRUSTED a92aa9b4c8a5bd839829b6d81bc62cf2ea542c9ea8d7e25127f6b74d0b93afb11c10ed9fdbe5c6b4b690c39d9ca434598718b089aab0de9941596a70b02cb49b39184ff0500aaa75251c64e31c1700586fb2323f476ab8ea4265443f1ffa564f49e135a2378f32b58c21feaab558cd965fffa2e77b67500256163047140ffeccb20428f257c12f32e409d3d1b1c82c245c94a402b300fc49b1cb5b2c9cdcc4984a7864f9388b0935808bb5dec3874c18d767e1fe88efbefe675c78c9fc33d950798c21ce850aa962c2baef79883463fc1db3523153dbc8d3f830e3470092772581e2861d2882b3ded6e5b6f18071a52981808749bbc8b18ca90d1f41aca2e6aa6414fdf499da21789ef34b54c7e31d895d7bc943c6025d97675c78ee865542784beb1b0a41b108ccf467fb28ac7d93f59a3d3b5da5242368c02131f2b8a38a25711d612f49e8e2a4a3509e2c8faabbb6eb0ff1166e8906c427354f183ac02d044e02cc63ee033d8604fd3589a6ef9be56c1b58e54788531e3e0b325925dce68f11f7778207bbf95ec1503b61799f65e14c7dd3e11d7cb5dc35665793fdf10f06343cd20d053082d4f02c324a358661772dc2c94f6a16992626a19332d77b18d4060caa960c95d893c6df22bb096ee07fc94de2152211b0755a0c90a7ee7368ae082e3d483dbb9ae39d052c446aebf8cd6bc450a32be74d99d2629b6782979e0c
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145547);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/02");

  script_cve_id("CVE-2021-1225");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi59726");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk28609");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk28656");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk28667");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs99259");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vman-sqlinjm-xV8dsjq5");
  script_xref(name:"IAVA", value:"2021-A-0045");

  script_name(english:"Cisco SD-WAN vManage SQLi (cisco-sa-vman-sqlinjm-xV8dsjq5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by a SQL Injection (SQLi) vulnerability in the
web-based management interface due to improperly validating values in SQL queries. An authenticated, remote attacker can
exploit this, by authenticating to the application and sending malicious SQL queries to an affected system, to modify
values on or return values from the underlying database or the operating system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vman-sqlinjm-xV8dsjq5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c58fb6c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi59726");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk28609");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk28656");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk28667");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs99259");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvi59726, CSCvk28609, CSCvk28656, CSCvk28667,
and CSCvs99259");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1225");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'0', 'fix_ver':'19.2.3' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi59726, CSCvk28609, CSCvk28656, CSCvk28667, CSCvs99259',
  'sqli'     , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
