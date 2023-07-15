#TRUSTED 6e94069ff6fd9bc640ea7d86ce9e0b521d927392c95c1ccfa3fdb439e04dcbc6bd4367e10bec41dbd69ff8c8fa2f0c8e0502eec1ca51e357e6f3a5fbad04a7fc87ee96b833cecd6e64377e8971d631d7d1991d6f89a6024e804ff35f41bca2bd104bab9df15ffca8b61ac5926285a68e5d7e7d9908e110ae69535835e6847678762e3cc046bc840827e53ad6fdec8b83866833b66f8e4d64c4eecde40a82242533db1db317137e74868868954396d58c10c73d2addf878ba42f3742343632284ff3d6d5319a67ef6e615c4acc7faafb1277327f222fda6007c45552b45c8da3bfce0c5a7f5ba16aec25f943cb171b3c5f6a53a8eac0229c19d99f2c7e74b4622c5edeb04409b3fa101a04629904f05e30dad8ac3703edb1288ee2d0a5ca7e901f3dd7ecb56e2afd68eda6f56c875c1ad26101435f3273137cd9d6709d53cb263f6a8169f1227666b94ff681a5fb511cdb5bdfe9c76741eb239dc7a031d408daa2b4b53d9c040c1a3e0747760859e396b4c79542c03886b06dfbaf9378725ead70113cc4fa35bee6641cb652dd1700bf6d00d94c113350ae02f35d2201e87a4ff2f381baaa0b39f1ca42ea9fd8246515115b4594c8b2f781b785d47568fd926a6feded0e064ac2e5a3cbfe8c72a8ce36f32a470ed5f649a391c60e7661db1fc61a859edd90d65e0e02421b9a4fb1a6f1e3ef63e650bfb050e2cb14f6df3f520a0
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140799);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/10");

  script_cve_id("CVE-2020-3530");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu79978");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu99038");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv05925");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-cli-privescl-sDVEmhqv");
  script_xref(name:"IAVA", value:"2020-A-0374-S");

  script_name(english:"Cisco IOS XR Authenticated User Privilege Escalation (cisco-sa-iosxr-cli-privescl-sDVEmhqv)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is affected by a privilege escalation vulnerability in
task group assignment for a specific CLI command due to incorrect mapping of task groups assignments. An authenticated,
local attacker with read permissions could exploit this vulnerability by issuing a specific command that should required
administrative privileges. A successful exploit could allow the attacker to invalidate the integrity of the disk and
cause the device to restart. There are workarounds that address this vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-cli-privescl-sDVEmhqv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4dec7487");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu79978");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu99038");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv05925");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu79978, CSCvu99038, CSCvv05925");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3530");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

model = get_kb_item('CISCO/model');
if (empty_or_null(model))
  model = product_info['model'];
model = toupper(model);

vuln_ranges = [
  { 'min_ver' : '7.0.1', 'fix_ver' : '7.1.2' }
];

// ASR 9000 Series and // Network Convergence System 5500 Series
if ('ASR9K' >< model || model =~ "ASR9[0-9]{3}" || model =~ "NCS55[0-9]{2}") 
{
  smus['7.0.2'] = 'CSCvv05925';
}
else if ('NCS1K' >< model || model =~ "NCS1[0-9]{3}" // Network Convergence System 1000/5000 Series
  || "NCS5K" >< model || model =~ "NCS5[0-9]{3}") // Network Convergence System 5000 Series
{
  // avoid auditing out
}
else audit(AUDIT_HOST_NOT, 'an affected model');

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu79978, CSCvu99038, CSCvv05925',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);
