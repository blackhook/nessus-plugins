#TRUSTED 380fb4d5330572a2f0b36085309f801147233965838ae996cc2b9d7c00b509b29689ca648c521be434f29940ab2761ada02edeed870c65c720272275cb4ca84cc033ed76d65689068b149008ba5fbc3905d1cadccb37fd74975f5d45e2de25fe4f4f96f6ebba723e4605835c446af1b2e65ef847b8ff9256ed9901ee41034746482f137616296dfb52c54257d0cf589cfdeaaee0faea3fe88d89b0dd4b61ea83dfbdefa6df649a15ad9a3aea38a0fb33351558a8f3e6ce0d4a685e8f21eaf9030c4189355b81bc334b9bac2b86f78057cddf84a1c2c51e3a6708a8d2fd83fa3a0a94e818e8bd035fec13636a1ad92db7e799bfac253f720acf6658bbc5b0c6b93f6987b5534de49a235a1d1a736eadf6b27026bf9a4f89163eaedf95748af8f94c5929749ef03bb8bbeaed582b7ba4ddd969c6233276e7dfcf71446fdf44dc29254933cecc2e9a6a946f5b111b616ac9c10f6085d0818060afe2b322b8456bd354e04167a91e657867605def25a52d8da80052438bff7c52922d1fffc6f55fd8b21a6d781e787253a0bcf52cecec7b2f8136ec1121ed65bd4dcbf39f79c9c0ebde152db81be8109a373732b8fb256fd97ba3f5f741c54e5ba3a7b9d7856820b19bfdd3879745472d8092ebfdef200a3105d993e2be781097ec1addb2c77a93b9bdb45e10af004450c9c22069723f03d3940791a00edc7428755d5e66ce3d347b
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155677);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/07");

  script_cve_id("CVE-2021-1444");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy20504");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-xss-webui-gQLSFyPM");
  script_xref(name:"IAVA", value:"2021-A-0508-S");

  script_name(english:"Cisco Firepower Threat Defense XSS (cisco-sa-asaftd-xss-webui-gQLSFyPM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a cross-site scripting (XSS) vulnerability
in its web services interface due to improper validation of user-supplied input before returning it to users. An
unauthenticated, remote attacker can exploit this, by convincing a user to click a specially crafted URL, to execute 
arbitrary script code in a user's browser session.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-xss-webui-gQLSFyPM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?327076bb");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy20504");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy20504");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1444");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '6.4.0.13'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.5'},
  {'min_ver': '6.7.0', 'fix_ver': '6.7.0.3'},
  {'min_ver': '7.0.0', 'fix_ver': '7.0.1'}
];

var is_ftd_cli = get_kb_item("Host/Cisco/Firepower/is_ftd_cli");
var cmds, extra, workarounds, workaround_params;

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
  workaround_params = [WORKAROUND_CONFIG['anyconnect_client_services'], WORKAROUND_CONFIG['ssl_vpn']];
  cmds = make_list('show running-config');
}

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy20504',
  'flags'    , {'xss':TRUE},
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
  