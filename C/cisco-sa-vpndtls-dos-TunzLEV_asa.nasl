#TRUSTED 162c93ae3c9961f6d965fd7d2f8622c3d53ebe03f25ca6340b403fcc5407088026bacef5f647a71193100a317d084d4b0caa646994199e407a46665d039b667d8ddc7adedcbe5a102921b5dbd22659b1296bdf8e300c2a36c88543166bbc560d5115e828f1fb7b95f5e12bc2dd414c97bd2f2e1b2bbaebbd88d2b7672f41b1dd182ee98404c0db4a069825176029757e9a78aa7f39b0c0a36a9149a23453600a04d61c92b8fdb13b02570f4171e3254a0d560499eb14ca79f0339c7c5357f8d3696c11dbf528601d7815a95b63c0f76947bddd3d738f38adbce2938a521d21d1529d6ef79931053bfce05f18e6cbaf5ab44d813b0b863cf51d27ebd2085c0307d99b8b535598e7bc48a148953bb974c834dbbfecca8058b15bc481ad9bd361cde38c73d9999adf8c6ab67964cb40ecc166438e57a7aee94c01bbe13df96f4a235476afc948ef05c86d643d3ba331bfb83f9fd122fd94904d9207b7c18fc0b75ccb97abdb9b25a9e157d9f2fc4ad193d44b41387b471d1090f3316635ff994cadf5036bf05d5f4506c243831dd821ef0c0b2946ef76484b820ad4b1d0f792f2ea086d68d9c5803fb1db68e6c80403521640262a1102ff2dd9fdeeb750df8d3ed12d957996066bc583bea8e743b4ccac4ad834672b4c6470e8f25204682fa1c3473bc910b2d420d0b15fa897eaa0af590fb21518bc45b0a20742d8ce236548b2db
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160305);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/01");

  script_cve_id("CVE-2022-20795");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz09106");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vpndtls-dos-TunzLEV");
  script_xref(name:"IAVA", value:"2022-A-0180");

  script_name(english:"Cisco Adaptive Security Appliance Software AnyConnect SSL VPN DoS (cisco-sa-vpndtls-dos-TunzLEV)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by a vulnerability in the implementation of the
Datagram TLS (DTLS) protocol that could allow an unauthenticated, remote attacker to cause high CPU utilization,
resulting in a denial of service (DoS) condition. This vulnerability is due to suboptimal processing that occurs when
establishing a DTLS tunnel as part of an AnyConnect SSL VPN connection. An attacker could exploit this vulnerability by
sending a steady stream of crafted DTLS traffic to an affected device. A successful exploit could allow the attacker to
exhaust resources on the affected VPN headend device. This could cause existing DTLS tunnels to stop passing traffic and
prevent new DTLS tunnels from establishing, resulting in a DoS condition. Note: When the attack traffic stops, the
device recovers gracefully.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vpndtls-dos-TunzLEV
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?864a3e06");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz09106");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvz09106");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20795");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '9.12.4.41'},
  {'min_ver': '9.13', 'fix_ver': '9.14.4.8'},
  {'min_ver': '9.15', 'fix_ver': '9.16.3.3'},
  {'min_ver': '9.17', 'fix_ver': '9.17.1.10'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['show_asp_table_dtls'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvz09106',
  'cmds' , make_list('show asp table socket'),
  'fix', 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
