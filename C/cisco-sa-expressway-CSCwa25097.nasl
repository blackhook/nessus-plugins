#TRUSTED 347e67c04257177f90606ddf2268b57fb9fcf892e1d3a103aa3de869b537d24f53358c2f047bb777b029002e19ef2525833bca922a4b804d28e18da8c77f6c24bbe258ddc653aaabbc8f2b672e3aa55842a0cfc7b43e33ccd6527bb77e1d64dc1f994cf176b09d027349380600ddb96a35f12641f1676f0de1e0cac2092a95278a1ed1e39716cfb60eab9b9ae66ad7f5adea07e9e37c1f04b0f9680f9f543713850552e7cd0aeba7e7accbc4164bf4b6d6526bf0561c9adb82754567ab949aac46d08e408573482eed61450e57a48974a6edce0b65522bfa0bd8c13b5683ff5c5a9331887b4a7a71be4c1ebab1fc1f9ca54a2af87ef1094b7c682416fe3914fb992b4005433dae890d61b612e1d394c2c48f2d200a1418a498a846d8b26ea9dc4720c2522e229b1f270280d64943f0a7234e97e727fad7873047ce30f184b2c22cc6f57005d1d9b20873d80e8b9e5ae0f28dfca0c8d68b7ae8a6b56f4d3b5812f4c6852aa919c929cd7d3439bf9dd375999c830729011b1204a4cb75535442c4b0b77f21092d47562a3b990813e9cd8a9aecdb1431c16f5666e99abad8e436c851c08907e61087272320c8aa6fd5fd045ecf286fe29c3b4d5d37a15aaa1dd09e01e5cdade54301e2c1d3c7e7678d07866734399ca656380920dd7448e3a07f0cfabaad713bf46d49ad28ec1901cf62833edc354f0f85393c9021b92c9b79fab1
#TRUST-RSA-SHA256 84aeecb8dc5358e9a47579d1894f36717f15a3c12477f998a3c7771ffd97277da733d2c2b6ccd4fe06a999b28b16bf5ebc99bb63bad7fd8d45b61129957f557c9b3a6be282ca327f0a6f85f2f65f33a53ccab88a25da2852e4f2a1d0cd3decee78a912995c153a2527a81ee2cc4957f700c01d32345cd15e4dc03dcee4b654b79bcf6e852a09a14075ae555d71f7f08d11b0f14c51e801968c5d43e99b58360542a92573b1c0f7e4cb3f469d453571b1ef07174a4de2b7578dd0dbbad2d71af216ab248447a8ea31f2c793e48604235738c3c98aaf9952d5b8775e9b28b3f0a1fffb78b2ebef9797ec72dcafa3464a3e79e8c4ecc77c4e837f5bb6f581a15208ef15bd2f33b4d9bcb7a63aed42ce51b012a77a9797c505c93474a3adce0b1a9b55f7b1a56a5fe6cc6d657aea09201c3d69c8aa8608117ad05f0a7fb3936f2ef4451cc63b1cd2308c4da67dc0ff3cc7721c3d5968fa8fe955e4c612803b1a5fa3b6216a7b4a070b3c8b8fa44ec7f61081f4629cee5293f07394581da8c63abd4aecb51baa161e8e73a334c22a7042fca91576f777b6c74f9331deef0c58704018f9ce1a5f71d3bb4f39470b74f660c3ede926358b76c1b61cb095571abb50e5d46c19d282c1b21cff799bc1803eed15df0004f53c5be4c1362faa0fb3ad6b744d9c3f09898a7034b01a70d254f345d94a44239f87efc77a9c54ad412bfa91b4c8
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165760);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_cve_id("CVE-2022-20853");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa25097");
  script_xref(name:"CISCO-SA", value:"cisco-sa-expressway-csrf-sqpsSfY6");
  script_xref(name:"IAVA", value:"2022-A-0399-S");

  script_name(english:"Cisco Expressway Series and Cisco TelePresence Video Communication Server CSRF (cisco-sa-expressway-csrf-sqpsSfY6)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Expressway-C and Cisco TelePresence VCS devices are affected by a 
vulnerability in their REST API that could allow an unauthenticated, remote attacker to conduct a cross-site request 
forgery (CSRF) attack on an affected system. This vulnerability is due to insufficient CSRF protections for the 
web-based management interface of an affected system. An attacker could exploit this vulnerability by persuading a user
of the REST API to follow a crafted link. A successful exploit could allow the attacker to cause the affected system to 
reload.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.
    
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-expressway-csrf-sqpsSfY6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b189acd2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa25097");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwa25097, CSCwa25108");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20853");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco TelePresence VCS');
var vuln_ranges = [{ 'min_ver':'14.0', 'fix_ver' : '14.0.9' }];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'flags'    , {'xsrf':TRUE},
  'bug_id'   , 'CSCwa25097',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);