#TRUSTED 34b029ff4ce981987b760e77e1d05bf91e6ec23af387fc59d411934ca78172158b6fb49901ec1524ef3e28d6936cc8379c00feabdb47db0b823f849c3152ec1d3c1544253e34ff75bcd85569797a8dddcfd799d7f69ea5a37121646ae05e317a5e99179597337b18ecb96f9dbf5735a91cb82db1f6b8bdb05b7c8e5535d523658a42d4c397e31126bb80d07d0a46e3af90feaa4fb19cd4df9f1b83ae59c1d070147c45ff36afcc3bb047366084cdba62cf7c70592d854203e75adeb71f15f42a1a3fcf2f021e4e1b129a6df086c77975011458122232e7bf952c418f3dfa82b009bdab6b8ddcc549b834046d27348bae1e4ba5d525d6b806f80b479f41aeeeb4b113da25534049029882a1c461a95d01366391d6bd3c62b1272f098a0359b224e21f0cee0e1d10c3703e84fbbc66eeaacd96cbef6a29bed746f30afbdcbca7e12d6299d94f58a6eeaa5978cf8803ddbc14aabb13d304439543b0e81a34a518d7a811bc3c3ba96671fc8cdb9ffd7ce1c4b903b5bdfc7811740491b34df50a2b1b807bb1cae445aa3297b230580981e628c60494b97d5f524645321afcfe3e606232d76c06d0b512c0f95045becc6300cd2f15094d43eb73f3d951b42420c1acbfc4690564ec96075979bcd5c3414b68512768cbc2bd1a05b6b7ed79b005679eb22d19d6279ef5153eb2aec3fc947f0d6064eab2acaef1159f8fac0fca499de1be
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151133);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/01");

  script_cve_id("CVE-2021-1462");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt11534");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-privesc-vman-kth3c82B");
  script_xref(name:"IAVA", value:"2021-A-0118");

  script_name(english:"Cisco SD-WAN vManage Software Privilege Escalation (cisco-sa-sdwan-privesc-vman-kth3c82B)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage Software is affected by a vulnerability due to incorrect
privilege  assignment. An authenticated, local attacker can exploit this to  elevate their privileges from Administrator
to root by creating a malicious file.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-vman-kth3c82B
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b8f24bba");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt11534");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt11534");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1462");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '18.4.6' },
  { 'min_ver' : '19.2', 'fix_ver' : '19.2.3' },
  { 'min_ver' : '20.1', 'fix_ver' : '20.1.2' },
  { 'min_ver' : '20.3', 'fix_ver' : '20.3.1' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.1' }
];

var version_list=make_list(
  '18.4.302.0',
  '18.4.303.0',
  '19.2.097',
  '19.2.099',
  '20.1.12.0'
);
 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvt11534',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  vuln_versions:version_list,
  reporting:reporting
);
