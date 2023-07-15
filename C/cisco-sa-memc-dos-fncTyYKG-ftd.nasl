#TRUSTED 622732044f8edefacc18ba1273e9b2e263fe76005e3e6cfcbf4ce9e800f3cdee7feed4bfea6a532caa68bad959d63344b962e89a38e0f0cd3ac82366a79a21b520094f2be522e60b9c530f53d1642a3155f1d8a56e41b485ee4216c7792762d9b8bb151eea9ae24ebe6ae0c86e6bd009c9a0a2ab7c771b1f517355efb4ac513354384401260a4558484d919391dca16524ce3d14f0530df17df71e3313b0fa080f46bfcd9ef20dd708b6c1494e39f2ba46341e1f613e206d8277c9cf8cfe901908aa003531a897d76eea05a97a5d4adfa0fef3ddcf6d3e505243ab52807f35219aa53d00d455e654f2f911ca1ce4ec4bd70239de3d7e170d8c7c5128e1f6cb0b4c8dd73d1a5022cd41eb2b87dba5fee83c778956d6fc8586d0e9246e8c0653cd344a8e2204fec0c912491c0cc62d085b60bd1ade3b0958b9b95f089bd8194b4fe028ce936d6cf9173acd0e142d87644b29c010b9fce2c324887ef4397924ac90c51f9e9e2d76c68e47f5e68b3a8fbb139e990cb44c5ce9ffd8186e42a0b613a31b2893e6911f97befed2e23efa724754eb8710c76d976171717ebbb3b643a36f00a68ffaa7a29a61d1923fea890034826462e20890f2a55eaa42aad98927c7e2faaa7c0261f6098411926fdcccffb6372c291d5a90daa0228562e5fde6bbe96e8034bc7e22e668364179113f16e7fc0a46355e57b07ed7e79a48a5773fa76d20
#TRUST-RSA-SHA256 2e0270b44d1acca8fdcde6d07c157563f07a1a07a80f7892905b94af6774f6a9fe59ca572924939ad738375cb41ba42c0dc2b3200a0554f3e277244177aa17c95f68ae16d0c529cd9084ac7c8dd42b651f47afdfc6f24fae9b92608784292e59e67c71abfaaa045f64cbb40677bcf77511dfeea42ee03e289a65a8bc5b698bb831788addc0f4508715719d5bc061fa319b7d9a9a23bd0efcd1b71ec998e07d7e68f426ac6525e44c8ecd00ced8dd390569374355ecfb9325a5de66c7f0401c3b50b3157b25d747d3cb005dc4cae76f96e81d61ff5700bbb487c555c64068f51228f1e49c6728a9eafe5f4bf84ceb8a70ba90e3316e84954e7ff7827ba4338eb9c4f7d893242830fcbbba09241860e72439a7714c5b4f4f0e3575cd44b938fc5f7e36e52eb26b22d8e43d1326425c0da99b353f538734614cc28afc41979f37916011af481c6a22f8862e01e4cdea39a02623aca62cd470ab73171c01c20407eb8f3ce772eb39ae229ce6c18077da49fb68352d93b2fe09e3226e3842187d62eebcc9c703ae2e4ddc574582e1b6433c9f391e554f4fb09ddbd5fa1dc510ee9323e8785ef944fcc04b2eb6baaf69a39e7794db44ab948cf3d65bee687f74ae984b26586654c9c06dfe3e89c7004ef11f36582260c250399755e55cf6a1a8a6b8e1d5c06cd2cd67dfd2b7a1305aba1b18975c31b85efc7f52dc9b83b11b5b3dffdd
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149300);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2021-1493");
  script_xref(name:"IAVA", value:"2021-A-0205-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw52609");
  script_xref(name:"CISCO-SA", value:"cisco-sa-memc-dos-fncTyYKG");

  script_name(english:"Cisco Firepower Threat Defense Software Web Services Buffer Overflow DoS (cisco-sa-memc-dos-fncTyYKG)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a vulnerability due to insufficient
boundary checks. An authenticated, remote attacker can exploit this, by sending a crafted HTTP request to the web
services interface, in order to cause a denial of service (DoS) condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-memc-dos-fncTyYKG
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4d5076e");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74594");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw52609");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw52609");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1493");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(120);

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
  {'min_ver': '0.0', 'fix_ver': '6.4.0.12'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.3'},
  {'min_ver': '6.7.0', 'fix_ver': '6.7.0.1'}
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
  workarounds = make_list(
    CISCO_WORKAROUNDS['anyconnect_client_services'],
    CISCO_WORKAROUNDS['ssl_vpn']
  );
  cmds = make_list('show running-config');
}

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvw52609',
  'extra'    , extra
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
   