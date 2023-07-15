#TRUSTED 3e54593919b246ff933ff01fd9128710d60cd31a4948d84ad835e171eaefb39df65d793d9a7849dc4087f244c8b2591b86590f089673f01c47bd53e6db11320dd696a76918fecc9d2a4bba2cfb86c85a17393336e6fe13c6a7969423b1cdc55365c71e0976b15ee8e24b291b41047ed2d07a852e8e31740ac5e027d74f86b5f99176e3db9be23633b11ccceb92c25cade8b65ab22a9c1419c67aabd90a79f99cc1949b315630998dc8f800c87b579cd5d204cf5c5718fbea6061a36011c5320be4ce72694a6bc674aaabe91c84b7eb6e3910332291a597b8128c89db11d56e5245a49fde30f68051a8363677969531521a15de25dd2919b9ee90ed84e489bc3d8db41bd698dd37179265284a8392edef269cd009c270eef4d97afd04e15ddaa1ac58f0491df89924952f2ca4f6ec299245564fa3c76249ef250718ecd5f4ba195efe564939d36035b8295413c8088164838e78400b23fa123dae2dfe7c755b15d0d9127628e66b82bc24ffb53801b50e6b4abc346139685d08562556ff499e123aeaaaf0a9a38ccb38a87cfc939d3a4ea7986e312473d37431ea63e96aed5a2113d910b5eb3befe0b9b6ed6fe3815687108eb37bc136acc36f0237dbc8ab039413afa4e43346c7d7bafdfe09b403d2be623c99596c82cc0c29ad74f5d0fdefa99b09bf1111ba62abb57edc76f2a838ac9cee370961bbdc9fc07d166d83b315fc
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160302);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id("CVE-2022-20787");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz16244");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz16271");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ucm-csrf-jrKP4eNT");
  script_xref(name:"IAVA", value:"2022-A-0178");

  script_name(english:"Cisco Unified Communications Products XSRF (cisco-sa-ucm-csrf-jrKP4eNT)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the web-based management interface of the Cisco Unified
Communications Manager (Unified CM) and Cisco Unified CM Session Management Edition is affected by a cross-site
request forgery vulnerability. An authenticated, remote attacker can exploit this vulnerability by persuading
a user of the interface to click a malicious link allowing the attacker to perform actions with the privilege level
of the affected user.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ucm-csrf-jrKP4eNT
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1c190e2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz16244");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz16271");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvz16244, CSCvz16271");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20787");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

var vuln_ranges = [
    # 12.5(1)SU6 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/sustaining/cucm_b_readme-1251su6.html
    {'min_ver': '12.5.1', 'fix_ver': '12.5.1.16900.48'},
    # 14SU1 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/sustaining/cucm_b_readme-14su1.html
    {'min_ver': '14.0', 'fix_ver': '14.0.1.11900.132'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['display_version'],
  'bug_id'   , 'CSCvz16244 and CSCvz16271',
  'xsrf'     , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
