#TRUSTED 91f20de9a7ab93ba9ca805275fbbdf6c49e9c6f4951c5cd4ae6d348fdbdc83456fee2c3e9559ed389b7c5f34283ca9f2bac1386bdb0a9c5ea9ac633a3a892ba03c8dfc6b311fa8ab9cd30058342e5eff51714cdbbfbe5712ce32667c0073cdee326d2103073c663ecdc96f009b6d022788d1d1bf4d69dd8010cf90304b3f102f5ee23350b6ad63d21dd0aa5dcd675e02bb0810698d40c6b6968b7a39569f1c29ed2c78722dbbf63bdbaa0b8c759d349bdc6c9a1b34cf4affa78126eb12d2041052dc212ef228877a06fc4ad6ac1c14de526661ae083243a7bd17b17be5b356f3ecaa67e516c55afca3adb2c1af63ca66b5c318fa5e66e10d01903339edbe455f55f5b5419aa30ee070bf8b375283e968c9154889be637e99f97a7c7253e3cda29d109a5a05dc32642d3ffc627c22007165957f7da9639f9cbe30c4f39b03ca27ba450ef957361785ec1d888d5ec437aa943c526775c5f33f1819057effa5a2a4155c41602628ba92f2a49bde9f2a3b44fb83ff55ce978b60170dea6a4b8100b4cb8190afaca917107fa7d403631087d119d257112cc8568cd82b1e01439675a7fdeb69d6da9c5fa3f67f4ef26fafa764b04b9bb8df882e52d3c09c1a67ea2f13ed5f1c21d0eebcd937b3b0804ecb1749f515d4857ac25b73ac2db7a8014ddbf8ea1cd52a1a302d9732e83e78bfa4d735429c970186605154be49a5abfead6a03
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133404);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-3135");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy76946");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ucm-csrf-NbhZTxL");
  script_xref(name:"IAVA", value:"2020-A-0044-S");

  script_name(english:"Cisco Unified Communications Manager Cross-Site Request Forgery Vulnerability (cisco-sa-ucm-csrf-NbhZTxL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Communications Manager could allow an unauthenticated, remote
attacker to conduct a cross-site request forgery (CSRF) attack on an affected device. This is due to due to
insufficient CSRF protections. An attacker could exploit this vulnerability by persuading a user of the interface to
follow a malicious link. A successful exploit could allow the attacker to perform arbitrary actions with the privilege
level of the targeted user.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ucm-csrf-NbhZTxL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d86741e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy76946");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCuy76946");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3135");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '11.5.1'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['display_version'],
  'bug_id'   , 'CSCuy76946',
  'disable_caveat', TRUE
);

cisco::check_and_report(
product_info:product_info, 
reporting:reporting, 
vuln_ranges:vuln_ranges
);