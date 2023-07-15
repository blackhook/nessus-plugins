#TRUSTED 5221b70cd9c6a59be4456eced2829ef9b99f6cc246f2bd2f0a7116729573b99557ff746a07ce43b27d274f89b19d2b14725121e926d902a2f87e274c5cac27b8a458d995921f3c8be61fdd366cf908f29516f1badf208549584841f38c8c2490accf53c0c5a8213c066ce9ea7867295bc83de66c17d539cf5e2be56c97be5c2ae10c12829c6e784c6cb43e99d6feaff862312d0a182cb205b6a4c583d0188d9f60b12e13b04b6b03069e897d07455f282fa66a0ea9fc5ffd46ff14b0df67db00ec4c54795fe156608d81b8d431d6c216f31d4d3d8ee914e696fab48def6374449924c3480874292f51e32692fdbf77ab323f3914c7cdb2756fbf1d5f1980db3538c1e6f94896d3cd68fa8de9270c94a100b7fb97441c2d66bcf3dd838260532fd3c31ea5729fb5530e6a526fc9de67e8c289e1e111166b52576ea5e50f16a952eb84874e7031ab9f3b5275bb5f9c65fe2a64f29cfc5ded524a6027c302ce37ebf6e460ccf1e71cc9919614488d9849a775a8c81d1d1d6f5406608303ac838f4957e9faaa1389be91cbf061cd940aaf1221fc657693e83cf18dcf17b5d11f584062c00a07d8daa47bfdaed303fed0fd485e8fea6ad50dea9f044c5e9ef84fdfbe9381ff1fe65f8094806d13f413d1a233d371df8400fb0ca43349f184a6f2b57c7e659d5686c9a39545cf9453844db1d034b2a5dba474eefafede0dfc5713e16d
#TRUST-RSA-SHA256 3ff6ce0af8e612b5da9dfcf33cf6560992e91c7f6c190bc3fc7889455b308589225d964c167437b40294e3bbd3d01f722206f5a0095938f647d7a5ef27795a749a122e8c5abdbc197eae4328dc5f6b747cc29ecf36f00d62301cc3aa54ec751d60342a29076a6ccd03a67cecee9c7ba971c66d018a81e94b15ca30b2e8bdda6f7421648283c6b6158ca19d8895dcf1d75ffe956c3687fe72f1588eef669a521b69fb73267bd59284d20b14242d5134d92c3ecd60653efdf4ba41b6fb9862b5fc4e2cdc954490237d9335bb7f7d110b62acc85a5fbe823ead53fae52dc50be9b6a2781ca4bfc68cdb9fce63fe4a0a8a9c87f0a05a5453bbb0b4e263786a5efd9ada6cf3a75155c973b1322e7f0e80c503ec22759dc6abcbc4aeae4d7bab42be23232421de5ea70082b5d213938a9708479f07bcc51e48ad94223030c97726188416cc5a4c64a9cfe329234c0b14d05e9688800208987b2b9be2692eb09b5638bcd483e0912be4baab09e73724126b4c6b70c9cb089b2a50a49e31be937fa294dcb5a1572ef2a58a0132332553f5006fc568a295f45d4c5890fdf2e2f932fbd8da177a2e236d3acbc736f2f67b292b81580b72bf3f5c4458747e71ace10639849ac8ee946c25d347231fedc2550ad4e0134f7996cba5ddf2dcb67b68c2af928dc3e1e77cd88de921432415ded5722f58572246ed5a030655a011101fda0785ea19
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166904);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/28");

  script_cve_id("CVE-2022-20772");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz24026");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa84908");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ESA-HTTP-Inject-nvsycUmR");
  script_xref(name:"IAVA", value:"2022-A-0463");

  script_name(english:"Cisco Secure Email and Web Manager (SMA) HTTP Response Header Injection (cisco-sa-ESA-HTTP-Inject-nvsycUmR)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Email and Web Manager (SMA) is affected by a vulnerability due to
a failure to sanitize input values. An unauthenticated, remote attacker can exploit this, by injecting malicious HTTP
headers, in order to conduct an HTTP response splitting attack.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ESA-HTTP-Inject-nvsycUmR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc1d0d7c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz24026");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa84908");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvz24026, CSCwa84908");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20772");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(113);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Content Security Management Appliance (SMA)');

var vuln_ranges = [
  { 'min_ver' : '14.2', 'fix_ver' : '14.2.0.217' }
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvz24026, CSCwa84908',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
