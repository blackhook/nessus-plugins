#TRUSTED 7ac7afe8db659c3878999d18d60b20783bfb3c5abf5d923a33582183916ded8db937057ffb44edb9848b0cd1021a2a4d6ef30ce94796dfe5772771999381c5defd2be72f1e849c017016ca974ac7b00331a2af5ede0af9b294e5a9e8b01a6e49759e3975dfd65849efe5040ade729275c7410d4b0f089c54ae8cffeb8afc44026df5d8981693e4a88732de68e3208ac9f10e2d7b7e22eb2e7fa628794da9b197dccc9905f8072b965d4ef4c3b12c014d5273041b7a625ebb36dd0f532eca0fef4e36f7e500fb843e2e084c26fc74e04a3e0420b49930071363851ce47e38d921c6bbf3898a56d7c2aa48edf2dc036ef8f72b6b04dc58edb3be9cbe702fd4f6dedcfb131154dc8a3028f03a4a36da3ed795c454b4e038ca2ebce3f5ad62f823d6e704a49720a4414f0606ea88bc5f3e5a032a9ce0442a35bfabf06a2c5f19cc341e05df8cec93b32282ec6123d0df1d53a0928026ef7398d252a2f5077891169c1f8f5b13ac1635ab7cf5c060bc376eca90111808efdca98014ab995db80662647ee6ac5b86a059f673e8bd3af600fb991ee32e6b058a4553466a60c53444b229cc6e49facbff596fad45f5f4d9a99502fa756697562c07f0c59072e82b09535dbe0e73c6765ddb8489bda82e498c435d6f128270fe9eebdce50f6e20f7f9d1df37b2e0c99f75e6d5d3919dfb56eaa578d449b691c782544d97f177ac6272157a
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153398);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-34716");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy96491");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ewrce-QPynNCjh");
  script_xref(name:"IAVA", value:"2021-A-0389-S");

  script_name(english:"Cisco TelePresence Video Communication Server RCE (cisco-sa-ewrce-QPynNCjh)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco TelePresence Video Communication Server is affected by a remote code 
execution vulnerability in its web-based management interface due to incorrect handling of certain crafted software 
images that are uploaded to an affected device. An unauthenticated, remote attacker can exploit this to execute 
arbitrary commands with root privileges. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewrce-QPynNCjh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?863c868d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy96491");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy96491");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34716");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco TelePresence VCS');
var vuln_ranges = [{ 'min_ver':'8.6', 'fix_ver' : '14.0.3' }];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvy96491',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);