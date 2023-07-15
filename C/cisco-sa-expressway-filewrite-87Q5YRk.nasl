#TRUSTED 8f6f43c20fffbb4c7afd7c57654cd3137ea7eb0f897b9b4cdf64179277923a9a004296d0458cf4b44df63aec0bcd91f9a4af3cd9d2d310823581dd18c223e78677ccf90ead393cda7c4ecce1c2b1942526b39f1eca0f2a154a23240a603b1574d80e8c7f17d4606240a33a92aee956e8c4da40c188129d47fb6dbc5f86e598a792c5f8ebe746e276dc0ea56f4eb00ada28ab6b0a38cf1fa2f7e41301d943e58ce6e89ac3a4d58358cfb782ab32ac8c74bda669b953855ea40e4f0e997af965f113569644bf0f7b3aa01e1c7f475fae85d70dec7312abb74b7229ab8f0c04c13c33363abcf749d8f6c43d1fb7b69ad7399aa3c0491ca282700fbef987f12d952feb82313e30430eaaa0a7b34bb97deb1ea7adc835948344e7a6a1e825ab9eb830e66b6a9438c87c26e5ff5c1ea99eecf722c468e34bea7d17eabc13f7b5e2608dae4fe415ac5f21f9fbc16eac446f819a85ffde39f3b7410e37d5898f27ed818239877bb439e84e1c385de04b881b84a023e5ccaef612df6859f25e9d2b9cc35534d0688488c471ba79ab48774409204c615b79bc977407e4e72fd637892ec3acfb25ea94bb54bc5658c16a68cf7e1d84a022df080c9135dcb7479a31d3ea274cf87817feb77f8984e23b785689a2b30039e43842c7207c583f0de02437e6adcfa0dbec108fa5571607b5eb905949fcf478e7ccbbdce8ed24b10320de980c6192
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158651);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/30");

  script_cve_id("CVE-2022-20754", "CVE-2022-20755");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz85393");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa25107");
  script_xref(name:"CISCO-SA", value:"cisco-sa-expressway-filewrite-87Q5YRk");
  script_xref(name:"IAVA", value:"2022-A-0097-S");

  script_name(english:"Cisco TelePresence VCS < 14.0.5 Multiple Vulnerabilities (cisco-sa-expressway-filewrite-87Q5YRk)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Cisco TelePresence VCS installed on the remote host contains
vulnerabilities in its cluster database API and its web-based management interface due to insufficient input
validation of user-supplied command arguments. An authenticated, remote attacker with read/write privileges can
exploit this issue, by sending crafted requests, to overwrite arbitrary files on the underlying operating system as
the root user.
 
Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-expressway-filewrite-87Q5YRk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?69a6823e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz85393");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa25107");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvz85393, CSCwa25107");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20755");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(23, 78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco TelePresence VCS');
var vuln_ranges = [{ 'min_ver':'0.0', 'fix_ver' : '14.0.5' }];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCwa25107, CSCvz85393',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);