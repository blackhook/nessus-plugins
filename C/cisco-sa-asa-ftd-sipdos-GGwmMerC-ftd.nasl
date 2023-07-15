#TRUSTED 2bb4db45d3efb12fcf8996e2f4fe76e24cf22c1d74a3690a4fce0a45bb8bb9da78d16c5b0bf7ee725bef40a4f1f70c875736e03be017c1f98ac5b1a113b4b5c61101683e515d12ea39229caf250c78c4b2ab613bc5255cfc58d8851543c81461e2a9a171c623f605d18c462830dea9ed55cf3637d331c10f9f36bc472cdbe0c18c62676c0c0888035ebf930279bea6f7c6a9597d5a5464250db1402a2fdb7e78e27c0ffb4dc5cce560b2d124af73fd6b738c66d1d48836469762fff2e81ec1ea3d19d5281bd641a9b24c42acfe3e06ecb34ca1162a79f52a7597b89c162fd197532d49237f9e919872c8985780e8823ebca6e9ce6acdd1842a0206e1f7b371a2d3d2be5a00e26cbe702341dd3313bf089d31b093c46e6b27bff14f073ecbc5a0ea8b91e184b01839d01c70024816051b84bfe8d4c458e1faae9e4bf37532fb8a8dcde585d1548c6bd47d972378574f4304275473e1fbd4189a507274b8822d1dee0b543f9075cfe6430ab53cc8f261617d9536b1f7150b8192cf511809f4511d5fee129637602a252742c4d99f7b8065a0dbd5cab8647ae286679e48726b21436cc984618884a4693bdce4b1fee9d8534b6d645836f36a57a4ca96c005b69cb91dc52b034fc85633184516371f085d687680bb9ba8bcb37d77867ed89cced871a7cc13ac5252c27327b7dd88b9486461fa01404f9606a29971e725f833c4a0d0
#TRUST-RSA-SHA256 1807bc4739542cdc88840fbbaa7b75c062ae861c7db75f63b8c9aed544ece6b4e0ca6053910177cb453780cb68d274e2e963c47b43a1abf9bb682131d6ae1ad56310ddb5e6713565f576fe3f3f7d0611f863e33c0e61a43598b9f1169d36cdd06eb62de25faa386e6e653591a86f27b9c375110a9ef9454dfed21aa7fc7b25a39f26a2df7bf4a1dadbd812ca89fbe0207f77ea344adf6dd85881dfe656d9550b41edf70a737977a642637894eecdfbc8efafd45067cdfe08937622da0e08cb270bba2ca9a279f3c56737fbcfbf01a5ebf9d568389af720340270ea6884a824373f77ae48f4afdc11ff2218379b2b680a42d111c5075e0631fd9fdf40db70536da805f042e7cf44edcccb978f62ee5f7287fa341f4c1e9769773540bd34d32c809fdeef08f7ad91f3ab77b4380643fed95897f07556790cfa7aedb1ddac5c40539ac0f68d1d9a800cdc36f591f96dae620b3b6c9007999aa6f57a944879e20ab1851575c1aba03cd723a938c78777524031be4e7fdd0a10de1a38c53426c5af42259205d7641fd8e9cb41c7c132194e57db56b015b00bf1126ac79bef199552c905b9fff74dffcc107a44f2584a2ec33507bda06328cb358fc3327bd1a001d0a04f9ec2027b311c88d302de299d7699b38a169bb0492658affe92f1b865c525deb85a9fef89c5bf4d019926fc44347c0eba341709c1fc2fab92b2ea6fcc997387
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149302);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2021-1501");
  script_xref(name:"IAVA", value:"2021-A-0205-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw26544");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ftd-sipdos-GGwmMerC");

  script_name(english:"Cisco Cisco Firepower Threat Defense Software SIP DoS (cisco-sa-asa-ftd-sipdos-GGwmMerC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a denial of service (DoS) vulnerability due
to a bug which causes a crash. An unauthenticated, remote attacker can exploit this, by sending crafted SIP traffic, in
order to cause a DoS condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ftd-sipdos-GGwmMerC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79f85bf3");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74594");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw26544");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw26544");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1501");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(613);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  {'min_ver': '6.2.2', 'fix_ver': '6.4.0.12'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.4'},
  {'min_ver': '6.7.0', 'fix_ver': '6.7.0.2'}
];

var is_ftd_cli = get_kb_item("Host/Cisco/Firepower/is_ftd_cli");
var workarounds, extra, cmds;

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
  workaround_params = WORKAROUND_CONFIG['sip_inspection'];
  cmds = make_list('show service-policy');
}

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvw26544',
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
