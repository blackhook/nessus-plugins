#TRUSTED 2efe84b4afe862f569be9b8a7e893ea366d97749c5a500a5a8c234c3594bab303fa9f9c4d0ca3f4c009123aadbb1b5c2759e57774a981ce41f3a566b5c43d69bee29a03fb362633f93af72082f5896e1ff62fbfd01e854270d620404adba39b40509f6ce07d354f55004f9aee78de0abd4b8ed266523ae34b88dba188ed11a7241aca17ce6fee50bd1e1bb579ce148b29c5d63ecb330a9db50c438bd41bc240089ad61d19add7c20ac523ad84a9634fcf83d8383e66be430b6875043b4c9a2786f7f8bff6cbf938b3a223a14faacb1e3bf9ef01b56982ea5328888f2c861511377a258fccae61312de73ceeb58d5c90684a22801ab8da41a2591b63ead2efb7cc2a50203402f802e9217f3bc459a56c034d2bb709d23bac1f74e1a06b99234df24d50fe3d8602395007e0a8651b2e3f9920a5f70b0add79284e406e6bd76438c90e9afcb04627f3cdc0d0fbc3a4d3a64f99cedf5487f429d4ac008696e9d36427ef70775c3753e3f0c2acef58d996d9541dc6e7f5c66627c94c28fba41e38efa83ee3eb6745fd10face67b23fe1caeb10b552daafb03a25a0d1abbb14caf9e985b1178a68b0afb2c0b4d20787f103153f61366dcdb16622cc4a32b2fc6ac198747551051a66bf5e8dd4652fc3ad08ef13e9668c243c387d0760a01a98e0708fc5ca43918a3be1473c7bd256f0cb8a7d4cab011b2368fb2593963bea977c53664
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137145);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3235");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk71355");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snmp-dos-USxSyTk5");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Simple Network Management Protocol DoS (cisco-sa-snmp-dos-USxSyTk5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software  is affected by a vulnerability in the Simple Network
Management Protocol (SNMP) subsystem due to insufficient input validation when the software processes specific SNMP
object identifiers. An authenticated, remote attacker can exploit this, by sending a crafted SNMP packet to an affected
device, in order to cause a denial of service (DoS) condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-dos-USxSyTk5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?528a5571");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk71355");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvk71355 or apply the workaround mentioned in the
vendor advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3235");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(118);

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
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

get_kb_item_or_exit("Host/local_checks_enabled");

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

if ('catalyst' >!< tolower(product_info.model) || product_info.model !~ "45\d\d(^\d|$)")
  audit(AUDIT_HOST_NOT, 'an affected model');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

version_list=make_list(
  '3.9.2bE',
  '3.9.2E',
  '3.9.1E',
  '3.9.0E',
  '3.8.8E',
  '3.8.7E',
  '3.8.6E',
  '3.8.5aE',
  '3.8.5E',
  '3.8.4E',
  '3.8.3E',
  '3.8.2E',
  '3.8.1E',
  '3.8.0E',
  '3.7.3E',
  '3.7.2E',
  '3.7.1E',
  '3.7.0E',
  '3.6.9E',
  '3.6.8E',
  '3.6.7E',
  '3.6.6E',
  '3.6.5bE',
  '3.6.5aE',
  '3.6.5E',
  '3.6.4E',
  '3.6.3E',
  '3.6.1E',
  '3.6.10E',
  '3.6.0bE',
  '3.6.0E',
  '3.5.3E',
  '3.5.2E',
  '3.5.1E',
  '3.5.0E',
  '3.4.8SG',
  '3.4.7SG',
  '3.4.6SG',
  '3.4.5SG',
  '3.4.4SG',
  '3.4.3SG',
  '3.4.2SG',
  '3.4.1SG',
  '3.4.0SG',
  '3.3.2XO',
  '3.3.2SG',
  '3.3.1XO',
  '3.3.1SG',
  '3.3.0XO',
  '3.3.0SG',
  '3.2.9SG',
  '3.2.8SG',
  '3.2.7SG',
  '3.2.6SG',
  '3.2.5SG',
  '3.2.4SG',
  '3.2.3SG',
  '3.2.2SG',
  '3.2.1SG',
  '3.2.11SG',
  '3.2.10SG',
  '3.2.0SG',
  '3.10.2E',
  '3.10.1sE',
  '3.10.1aE',
  '3.10.1E',
  '3.10.0cE',
  '3.10.0E'
);

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvk71355',
'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
