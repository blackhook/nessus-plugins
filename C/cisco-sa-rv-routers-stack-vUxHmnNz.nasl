#TRUSTED 99841a95a2a92e08378a9933b47699ad886caff6c73958f7968f04b6cea2fe5f937b58f2c13891c6dd0614a81399ff09b46f2687ecc40d6076e339d3af17b9690e24b122c9bf53ee7b57fb3f72ce3f1f72476d1e89e031a3cf2cb5df2d06ae74f095e6ae077055e5075e1d766d6b8f3b0aee0f6f14ece77af92bb7a30a1cb92c296168d0b6f7e1436904168e2e6ac805c15d2b8995a970c16a67e4aef3dad8a8e6215b6ed26de814918a4c4e8a6fad11f0fc762a7de3903d502e2cb439c450273aeee6c77cac7f442e7abd14dd0ccd4dc117b76386a22d7fa3dfd3f9b4fabd13a6c7b2a2a7568eaf7746c415c8851ea7aad5d5d556853fed5ca1f467449d494965f447a64dfd311ac2177c2f2cde60564e8d36426e30758a2b3aa2785af6f55ad8dbc2aca158d1f7d40700949913ff5ef276f52e1ef4b1df53afe8a01f173af8cabc1b2e4fc564c4e64456b51cf9e103ec48ede278048a5a34a6195c36d04fcc3b3f4c7955c19021f97a5f334d34580fadb335b451cae01096913aacdf686b2f94c51678b9645e9a82157f27b4618cdfae02464938e43aad713c7b874cc7cf24f106cbd430fe00adbbc0c4df8f73e19b2f4322a692e10d2a729f6a46a7b1ef8856596fbafc1fd4293bf9556610d741d91a4839f92b04605fe4d305b9a817d5d9eddf18ad565ab48563ec5bab6b893c74168159d491452257a7a344cffd023a12
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137852);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id(
    "CVE-2020-3286",
    "CVE-2020-3287",
    "CVE-2020-3288",
    "CVE-2020-3289",
    "CVE-2020-3290",
    "CVE-2020-3291",
    "CVE-2020-3292",
    "CVE-2020-3293",
    "CVE-2020-3294",
    "CVE-2020-3295",
    "CVE-2020-3296"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt26705");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt29414");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv-routers-stack-vUxHmnNz");
  script_xref(name:"IAVA", value:"2020-A-0274");

  script_name(english:"Cisco Small Business RV Series Routers Multiple Vulnerabilities (cisco-sa-rv-routers-stack-vUxHmnNz)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by multiple 
  remote code execution vulnerabilities in its web-based management interface due to insufficient boundary restrictions
  on user-supplied input. An authenticated, remote attacker can exploit these to execute arbitrary commands on an 
  affected host. 
  
  Please see the included Cisco BIDs and Cisco Security Advisory for more information.
  
  Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
  version");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-routers-stack-vUxHmnNz
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d21c4b0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt26705");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt29414");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvt26705, CSCvt29414");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3293");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

vuln_ranges = [
  {'min_ver':'1.0.0.0', 'fix_ver':'1.5.1.11'},
  {'min_ver':'4.0.0.0', 'fix_ver':'4.2.3.14'},
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt26705, CSCvt29414',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  models:make_list('RV016', 'RV042', 'RV042G', 'RV082', 'RV320', 'RV325')
);
