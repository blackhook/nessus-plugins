#TRUSTED 01ed8354142f0c3e31f98de15c12755ae9a52c51c3f9dffc57e603dfe06c026446658cdbb5467be107c4f5243e35c22b41117385627fac50dff2391c2bca3062bbb4e3466e46357f51cd7e73c6cee45c88f6f75684e2538b5a8e8208537444332f4a9e2e041712445e495d98e64db2e7b8ca2a7675373c6881f9c08d1b64f263e30fb9ddfd0818bba1f7726bdd254b1a2311354300cba3b098e93a9803fa684503695549989d33ebb7cc32a2e5e4406ffe56afe9f51dc1528b8704f8fc43a7535932757a71414e2b4bb8dc1f7c504a2159b51ece3c050c39db87e9b01a69af14ef264811144622269d9e995a55d2c8d8cd6315ca15357ad0dfe9779bf14d203d0f24b65a134dbd899968ba19b61cf3e2616c042a12449631196175ffb6868a3219d9123a98ad31f9ee5f204a38b940e5936aee0122faf879dd08e97508b36e886a3b2210a8ff81a38fcb5cb6dafb79b266ef0b8ebfe4e7b53ff568fea710ee03e80813a8f4e240b383351b551a992d85cc093c7d0df8f408c6cb742ba82b35c264bd44aba3d6f28cb90936aa365127a9ba4c874fec46cb7910f6b8718445c80cf0a1719d9a2e8cdd16140f8c03b3374a58e36471b8a786b8b203366abbddf7df110ce563d48d607470cca1e52b53cb09848223201afae54fb48ea87f0dc1276916b66560d0203702cab7ab3cd35ad87d1b557380360410c5e3aa06255f153d5f
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150051);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/28");

  script_cve_id("CVE-2021-1232");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28397");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwanvman-infodis1-YuQScHB");
  script_xref(name:"IAVA", value:"2021-A-0118");

  script_name(english:"Cisco SD-WAN vManage Information Disclosure (cisco-sa-sdwanvman-infodis1-YuQScHB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage Software is affected by a vulnerability in the web-based
management interface due to insufficient access control. An authenticated, remote attacker can exploit this to read
arbitrary files.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwanvman-infodis1-YuQScHB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?561b8fd0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28397");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu28397");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1232");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(522);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/28");

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
  { 'min_ver' : '0.0', 'fix_ver' : '20.3.2' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvu28397',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
