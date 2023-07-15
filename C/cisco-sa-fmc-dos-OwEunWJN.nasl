#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168869);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/19");

  script_cve_id("CVE-2022-20854");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy95520");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fmc-dos-OwEunWJN");

  script_name(english:"Cisco Firepower Management Center Software SSH DoS (cisco-sa-fmc-dos-OwEunWJN)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Firepower Threat Defense installed on the remote host is affected by a vulnerability in the 
processing of SSH connections of Cisco Firepower Management Center (FMC) Software could allow an unauthenticated, 
remote attacker to cause a denial of service (DoS) condition on an affected device. This vulnerability is due to 
improper error handling when an SSH session fails to be established. An attacker could exploit this vulnerability by 
sending a high rate of crafted SSH connections to the instance. A successful exploit could allow the attacker to cause 
resource exhaustion, resulting in a reboot on the affected device.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-dos-OwEunWJN
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a73e7c9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy95520");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy95520");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20854");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_management_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower_mc/version");

  exit(0);
}

include('vcf.inc');
var app_info = vcf::get_app_info(app:'Cisco Firepower Management Center', kb_ver:'Host/Cisco/firepower_mc/version');

vcf::check_granularity(app_info:app_info, sig_segments:3);
var constraints = [
  { 'min_version' : '6.1.0' , 'max_version' : '6.1.0.7', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '6.2.0' , 'max_version' : '6.2.0.6', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '6.2.2' , 'max_version' : '6.2.2.5', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '6.2.3' , 'max_version' : '6.2.3.18', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '6.3.0' , 'max_version' : '6.3.0.5', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '6.4.0' , 'max_version' : '6.4.0.15', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '6.5.0' , 'max_version' : '6.5.0.5', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '6.6.0' , 'max_version' : '6.6.5.2', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '6.7.0' , 'max_version' : '6.7.0.3', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '7.0.0' , 'max_version' : '7.0.4', 'fixed_display' : 'See vendor advisory'}
];


vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
