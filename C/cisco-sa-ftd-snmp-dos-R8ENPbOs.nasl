#TRUSTED 76db21a607892ffa97e62927d2b041ed6575ebf03340da607740ca0256748cf8e4b9bc598bda63d32abeaba21259716b36a4d7f892a9263e37510b116cb8415e3e604b7fc32b1045bd26e922cdda7f1fc5122d999d4e7006ad3b5d2c0bfe7603f02a70147520e8a7bb2ecad3faf69d2ea409e7c5e4a4e84094732ed72f4013cd908016ef58654c102cd1c1444b4a959d0dee39eee5267af62418fb89255291f62620df925b2d03f6a110c126ac0d400990cf95a71aea4e07728ac5538541ad629abd35be1ee7b9a33a96e1dd5d3b8d3f8e9ff4b2b6e61bc73d6b0c15e59119202d339e90692835b3ec1dc0306f76a10231c04ade3afab13db514a5c16d8b3b3e3488449e7e7eb7c19ea25b334d38f1cedd2ee9c0160cd64da613159ac9e0237181a5dab2adc711ab78986d7e62a2cb6a51cfd8d19d6a4c2a5425201737267b4f780333b86a749018b33dcf64394478943e4ef52baac54e2c5c88ba459c346ad877c55dda7912d38dca00c62303ead7605155836ad696447522967644ddcdfd9adbff145732ec4ee5fb87cf8bfa971f0fe9da529521f336a4924521d0177510b1e5c983ffdb644ce79596c0ff6783b06802d64082c04633837d15ebd08b5d5c6aa8df9e834539d5f76122838f4305329360f74cf48c7e7b8ec0f3f473d09e5671833bb4172d6114c83f82fa4feed97cf345fab03a29371c965d34bb87ae89b213
#TRUST-RSA-SHA256 4bfc725fb2568993f31dd9c43d84b5c2b51ce76c326d451e57d7647dccbd4884928f8da372173ca11b0850a3fcdcab159c460a5dafdbbdfdab04075f46edc9f21280faa368869752c5833f79821406d43004cec48981dd2b38dedb04b86edda83f066c99fe30b0161c44db587a2d4e72a5b3197a8ca57b08be297e3b06b0cfa9f7afd8771d9fc12d2cbf5fbf1a080486515b97b77ceb18d315dc6138698e3600b175e4baf9213dc4795f82f6559cc41f2c7136a0aaaaaea5e3286258fb4e5cf06b59452511cceecd1d5ac110adffd7535664a308b0a7faa51e1fde76f621a7964c72f6b128220e33bce811617d5dfb132cb446395eae91ab8e514dcf57f58c10988bc01bc165acdfe011fd52851b72889eae196ac26c05c8626fdbd15cea03433f8a28fd2a2d0dae00ab0ff3dfbc2c7c724dbf12745875f38a14289a9349b5e2de4ac886b2928c6ff4ef7ee60786da02c9f6aa2064a556cd37821441f19a3a9371a0e3b339d3b5d8082f7948a0b180275f7ffd27b2344dd0e3682579900a88071c66f57a0a95138c4da120fe03d3276371666a675b5e9711fccb3040d703b5df41d1d3205b9db6411b324e4babb15dd4e2e4fe70a6cef8cda13429681b2f598092f7d8d60862ae8be3084e48776833672857d7e710197c44ba03d577edd5378de9dafbbe476153246b22050e469c6b7b4681b5890783f5b96f53221e3472b3b0
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152485);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3533");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu80370");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-snmp-dos-R8ENPbOs");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Firepower Threat Defense Software SNMP DoS (cisco-sa-ftd-snmp-dos-R8ENPbOs)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by a vulnerability in the
Simple Network Management Protocol (SNMP) input packet processor that could allow an unauthenticated, remote attacker to
cause an affected device to restart unexpectedly. The vulnerability is due to a lack of sufficient memory management
protections under heavy SNMP polling loads. An attacker could exploit this vulnerability by sending a high rate of SNMP
requests to the SNMP daemon through the management interface on an affected device. A successful exploit could allow the
attacker to cause the SNMP daemon process to consume a large amount of system memory over time, which could then lead to
an unexpected device restart, causing a denial of service (DoS) condition. This vulnerability affects all versions of
SNMP.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-snmp-dos-R8ENPbOs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f8dd6a4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu80370");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu80370");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3533");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '6.6.0', 'fix_ver': '6.6.1'}
];

var is_ftd_cli = get_kb_item("Host/Cisco/Firepower/is_ftd_cli");
var workarounds, extra, cmds, workaround_params;

if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);
  else
  {
    workarounds = make_list();
    extra = 'Note that Nessus was unable to check for workarounds';
  }
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['snmp'];

  cmds = make_list('show running-config');
}

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu80370',
  'extra'    , extra
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

