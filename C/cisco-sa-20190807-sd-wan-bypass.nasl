#TRUSTED 90774ef8ae0c18e197957a7d4365f1008fa4e23f1c163e402d37672b6f7065a830227bf21c59ea147ab6108e14840177bae4b8beba178391e1e88b31e6f0f5a38e26e0fc36971710d0d1b4c70430a974c35df77e7f9e62e26c7331c7c5e8af18d238bc008a3dfbf5628f996404060560d9d5f522cc7ee8addf57a50758c132e5d0309da1a1c8e8ed334b2b250e956b6cdd2e994bd045d079de7a6e97bd3e6f76a547f3d56077a9298fee7d9f6bee714ead3a56dfffc67fcd19ea3e6243ac756797c1eeea2a61e434d9923868184a0aa90945bbef29296e8430de93a88c52815d2b03a4a119d4b0b4528a5aed88b0f066a75ef6576b3b4447bf70daa25f99c9153178c9e413892620ff7d18fcd3c1514346c5c60643b50d135a993565f2478f40359f9c15a55fb2414180577f1f79a0f90c8777a56d801c72890469a19d7122aca136f3654bb6a4f6242b575cc62b2b03801c0519aab0324f399209787ac9b1f013b1fef297aea447031b4f626234ff9f51dd392a6eee9392e8ff8084add440161d240b11c945f95c30d8034f5dd1a25f86b0acd774384e46da21f8800030c7612f698a2afff849524fe907eb1b5236c598bb9a8fa77a83a6f0ba84c478c17e9ecd5fcb8a6ebf33fee2a0a6ca976c1ffa974978e1e9b7ba2b63e09a2991307ecba348ac76565b20dd9b8a7673b9b9f36c6cb898463d352cf4b127d6c14c7166c5
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147761);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/15");

  script_cve_id("CVE-2019-1951");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn67202");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr64177");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190807-sd-wan-bypass");

  script_name(english:"Cisco SD-WAN Solution Packet Filtering Bypass (cisco-sa-20190807-sd-wan-bypass)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Solution is affected by a vulnerability in the packet filtering
features due to improper traffic filtering conditions on an affected device. An unauthenticated, remote attacker can
exploit this, by crafting a malicious TCP packet with specific characteristics, in order to bypass L3 and L4 traffic
filters.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190807-sd-wan-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1491c7e8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn67202");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr64177");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvn67202, CSCvr64177");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1951");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

model = tolower(product_info['model']);
if (tolower(model) !~ "vbond|vedge|vmanage|vsmart")
  audit(AUDIT_HOST_NOT, 'an affected model');

if ('vedge' >< model &&
    ! ('cloud' >< model || model =~ "[^0-9](1([0-9]{2}|k)|(2|5)([0-9]{3}|k))"))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'0.0',  'fix_ver':'18.4.4' },
  { 'min_ver':'19.0',  'fix_ver':'19.2.1' }
];

version_list=make_list(
  '18.4.303',
  '18.4.302'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvn67202, CSCvr64177',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
);
