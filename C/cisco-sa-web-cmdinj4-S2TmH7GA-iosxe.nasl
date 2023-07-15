#TRUSTED 4d53e3126dd877a48e16cfb820d146c90ddb16f3547b4a01524f3ccf154be0593d156207058be9723821bcee467d5b8bc4bd69551a0abf14878ecddde7137a4e4dc15287fee555ecf0688793b1b3e2b440bed0241318dcbf55a8040d8c2c510426df15b0bcd9721f6558c6e53e31d40549d8ee5704e97d5e5e2c84e6fc6f51c1871eac9297bb4590ffd4188971271fb3797b9ee2edfe362d2b4d1e162d294329569a20fcdf752329af021fa6db7c0a2e80281248faa9474864de40dcc672a2288d9523ad6fcdde4bbf51b91de1cad473b8cd89891e7332bfca978d4ec49db717c140ecc6697ea423cee2bba07212a7b83ae92b7cbf25aac743b23de08f1aa55a55213fe15abe0b6cb893f8b5e49315871e0373509cf2472531a455104b715161506a9ad176cefd95807c42c10d2de001d18f868413defa3c60d8dc19825c52b1e65664a695de11ad67c225b466338a7f21ee181860dbc22b33287f5a24a5103d7ed9669fe378aff8721a6c9ae1ece68d17d1a42e58442a9fa150b23001f5e25e3b093534390c399c107f094848f582142a1371e183be8b6c6950aea5f4702835c8962b2cd4c5666e571c68e1a9ffd1c5b7389072e7db03217a4a1766ac9b4694ca69700af959ef2601e1c6326a05d7620e6671cf70870235bcce1af1a3d8395d4b335957260ebf64c14f003fb59334e718e4a05c1499095e6ecfa11722a5fc13
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137185);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3211");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq32617");
  script_xref(name:"CISCO-SA", value:"cisco-sa-web-cmdinj4-S2TmH7GA");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Web UI Command Injection Vulnerability (cisco-sa-web-cmdinj4-S2TmH7GA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-web-cmdinj4-S2TmH7GA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee496248");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq32617");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq32617");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3211");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

get_kb_item_or_exit("Host/local_checks_enabled");

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_list=make_list(
  '16.12.1t',
  '16.12.1s',
  '16.12.1c',
  '16.12.1a',
  '16.12.1',
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1',
  '16.10.2',
  '16.10.1s',
  '16.10.1e',
  '16.10.1b',
  '16.10.1a',
  '16.10.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {'no_active_sessions' : 1};


reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvq32617'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:vuln_list,
  workarounds:workarounds, 
  workaround_params:workaround_params
);