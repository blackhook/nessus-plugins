#TRUSTED 877822bb61267af01b648a672629dabe1757b145c858508191e654fcde929b0dd2af8a26924b7c99e51ca934dda9efbae2d3c04622e536d7ce5ca224e32512a6d933ec761ef0044fee17689397ecff0b4507559ed2aa50d360f976c5f109bf56a0559ba57606d50200eded86632457abeb02e01e93d73ecfc97502e2182e85eb526c2738632d47049aa484b8e6884d10814a1b97c04f55fa87ed47c6b3115f63fed1df943c31a3f0cb98969a7453e663f7265a4248a0f5a2f00be49a7b8006e72b5173cf7df5abc6e2c6d8bbda0896367273c12e765c5191c21a97a7313c69d2fff4289fa613d003437aa9e709bd2f84a7650f10744eff148a6c2dbfbdf3d7c987beb697d53f2418fc72aaa70b564a09eb1952d481f31f873a89f15f2fc772bb19b1c905f4d87149456d5d0cb48f534fa9177f1af5cc233eb119530cc1f17909f8a8d355adf83f01d806c59c2b9dd9a044d519cd886ba78b4329d6dfa7eff8c7706977636ef357001dde4580c63579237071ba97ebda0048d3a0dc7095bfa1f45736d5d3fb52bfdeed8565960241d08ffe53298430aca18f26b51a4d967410cb793b547a4d62aa1c0e1fc2ed50eb58147d29090e74865265544b0d149872692b801148a1610230eb1099981b87cc9f7d324f4f1ce727feb67360a6eb444fffc684d2d044d9ec8b6e6a424a068a55795466865309ef2098d4bbe8eee469cb8a6b
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155451);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/18");

  script_cve_id("CVE-2021-34781");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy13543");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-dos-rUDseW3r");
  script_xref(name:"IAVA", value:"2021-A-0508-S");

  script_name(english:"Cisco Firepower Threat Defense Software SSH Connections DoS (cisco-sa-ftd-dos-rUDseW3r)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a vulnerability in the processing of SSH 
connections for multi-instance deployments of Cisco Firepower Threat Defense (FTD) Software could allow an 
unauthenticated, remote attacker to cause a denial of service (DoS) condition on the affected device. This 
vulnerability is due to a lack of proper error handling when an SSH session fails to be established. An attacker could
exploit this vulnerability by sending a high rate of crafted SSH connections to the instance. A successful exploit 
could allow the attacker to cause resource exhaustion, which causes a DoS condition on the affected device. The device
must be manually reloaded to recover. Please see the included Cisco BIDs and Cisco Security Advisory for more 
information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-dos-rUDseW3r
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?012c685b");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy13543");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy13543");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34781");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');
var model = product_info.model;

if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'Cisco FTD');

if (model !~ '(FPR|Firepower )(41|93)[0-9]{2}')
  {
  display('model [' + model + ']');
  audit(AUDIT_HOST_NOT, 'an affected model');
}
var vuln_ranges = [
  {'min_ver': '6.3.0', 'fix_ver': '6.4.0.13'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.5'},
  {'min_ver': '6.7.0', 'fix_ver': '6.7.0.3'},
  {'min_ver': '7.0.0', 'fix_ver': '7.0.1'}
];


var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy13543',
  'disable_caveat' , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
