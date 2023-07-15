#TRUSTED 93d2a3e096445b04509c1b4dcc22aadbd9721c080186da5558fcb3f09b022e3979812891392cec117d5df126068ca83074b82c113ff6dee328f9da902c7f00ffa7a30994f58fb301aa0ad5ca1a342f28bceb3a69b7afc1c9277b38108abcf85a39be53d1beae6068604fcd546a28436dd941f336233f6e123349f99aee5460cf8fdcc6af5cff29fa53cfe50958fa9083c6d8eb5728bfd129e107b30c7f1bec6057a657c5e4d873947900f933c9c8342ed100ef8c9ae7918ec8a1cf1a01dbc85cf65ce59fb4ed84a9cb1a73cf6e7701bdf143f62e38ada66941fef739ef90d1a5c2b4ecbc76c7c368d6fb58a208bfd150abd278678f5459597674638e4e3a09af6fb8438914f5711a3dd6460d8d2d4a06b8d6afdc78d9ac8663bdbdcb6f82e4f857f9bcddbfa491e54ec7f03201da4026a085dde5c464c57109f56b050027ea311a53b522d4a20505089629a9767f90b7f22dab6b46ae140fb8046772da43376ecfae7443aeaaaecf5523a58dc718c2ff87ec99d9a897d0aed21d138bef4b268a1aabb4a100b7fb8032556aaa18514b8c30064f02fd9c8cfbd5bcf3183e25e134a58819d486688264677a69464fb87589096b1669163684ea92c01ed433210e713f7fcbf65f57227859f1c69b7a9812bddf66b93a0b86c1a76c922e40e332aa27f6bb4e0db460b11922b6f3a508b1eafbe137bcf031127ebc0d2b21dbcccd5127
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149455);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-27122");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv08885");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-priv-esc-fNZX8hHj");
  script_xref(name:"IAVA", value:"2020-A-0500-S");

  script_name(english:"Cisco Identity Services Engine Privilege Escalation (cisco-sa-ise-priv-esc-fNZX8hHj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Software is affected by a Privilege Escalation
vulnerability. A vulnerability in the Microsoft Active Directory integration of Cisco Identity Services Engine (ISE)
could allow an authenticated, local attacker to elevate privileges on an affected device. To exploit this 
vulnerability, an attacker would need to have a valid administrator account on an affected device. The vulnerability is 
due to incorrect privilege assignment. An attacker could exploit this vulnerability by logging in to the system with a 
crafted Active Directory account. A successful exploit could allow the attacker to obtain root privileges on an 
affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-priv-esc-fNZX8hHj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6392a8e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv08885");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv08885");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27122");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(266);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");


  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'Cisco ISE', product_info['version']);

var vuln_ranges = [
  { 'min_ver' : '2.6.0', 'fix_ver' : '2.6.0.156' },
  { 'min_ver' : '2.7.0', 'fix_ver' : '2.7.0.356' }
 ];

var required_patch = '';
if (product_info['version'] =~ "^2\.6\.0($|[^0-9])") required_patch = '9';
if (product_info['version'] =~ "^2\.7\.0($|[^0-9])") required_patch = '3';

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv08885',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);