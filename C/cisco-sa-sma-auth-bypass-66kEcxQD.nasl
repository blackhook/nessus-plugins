#TRUSTED 3d5ae4dc018d64ff3587c18fb741e29883e53896bbd4b5d2188631cd769309f96e266912196cc03019f4effc85ef5cb81e5952aa28c9925a736f8c9f47287d32e4e585f776e7d537d29e6a5ab88e26852e46885f1185e3adfe272cd5a637ad600c755fe5bfe83ca77fd4e31d78f984c41b5fc8f6c18a4f7819aa59e394f2dd51d072f61cae747c2e608d4c00232467eb226e2bd27bbf4e7c6b6f67990d1afccf7f1da4dd7c12d5578ff758ed06cc2d735458c8674d6b660eb00372961a5eb441599b340979698aae5a2294a5b3e6c1cb7a953abde864214b80a1713d98db11e5262a39cbf0af33b8b9f6f93d4fe14a8d606fafee64f0cd3369a447d75a4360481efcff688cd73d93ab6fce04c85dcfbc22414474a853c4eb757acb19b9c18b6775d3c207a81b2a898afed97df9945ee50908afe108ba74552a54943b5708ce6eef1b78c42561d78722fb44b82c6a202a1b1ecbc1b4fd74990a85ed28e8d8f748bd57e89eedc73fc1558cc10ff785e94406d880d1f62c87d10342975960eaeb44b30e4710b639c853316de15f0bfcfa8e61416bdd1f3d0bc72740e527ba5de1108379d263f2540ea058a048717bc996d5d96abbc05df27c495df5654de930024047651f0427a7bbde6c2c31a805ad9e1aefce2f59a044da6a495aa4615bc33bb5e3279f9a5478398364067fcd8b5b6e7fdef07b18209aa1998f1595f8988ab9af
#TRUST-RSA-SHA256 8c5f645e4821584e3ce1f6ade6530309507ed888b73869381d14bfa481cc01a8740c175c46b77515245902c2dfbe545d0181a11bd68c0e728549db81045f2b6e4a138a6ad2dcc076fc71f269041e43136ea354f3179c8e1534e7d4326ec4d35102a83a449057459608d58ceb434ca70348f3397f84cbaf08bfa0a2a4e7881873dc2cba0ac5dfc03a5758c446c6ccfa2254b3a8f8dc501c057862f06abef225cf8c74dd643cf05f43d5252f2d2cd129f592e93eeec157abed43f5dad0ed426a33a6dd182f4bf9149b48ea100bc2d1d7861ff48cbecf75136eadd11212af0c1aa8451a076e30539ea4a4697f8144ed04584b6f756ade22b1cc96e344a7d65a30a1c2cce1becfd2370785e962478b3e499b1878431dcf67fc5bb19e8f3af87d505d4c3a9f1180cab19b0c90b67f5db316883077134bd2a0e7a339e7a95204dce21f73ae76b27360ab9fbacaed2939d6f18d4174f699d378d3832b7a1cf2eeef3744153b1b5a862133252174b2cdb76e820327795938c7e9a29967e0b787440d85c7481a18c7715887ee69a871dea13c41b92a27b307eeabe7bde11a294389c6f31625b7b4bcaf20fc451e27ff7ad936b38dd744e4372fb714406a73639e85ed2fc31b60231b0f7c52b765283524a3435aa5cac781d955db58f7455668b9b1578fc033c8aae5583f66e54ef02693c8e140a30a68f01fe0c2af625cd5900ebfe63f48
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163475);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-20798");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx88026");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sma-esa-auth-bypass-66kEcxQD");

  script_name(english:"Cisco Secure Email and Web Manager External Authentication Bypass (cisco-sa-sma-esa-auth-bypass-66kEcxQD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the external authentication functionality of Cisco Secure Email and Web Manager could allow an 
unauthenticated, remote attacker to bypass authentication and log in to the web management interface of an affected 
device. This vulnerability is due to improper authentication checks when an affected device uses Lightweight Directory
 Access Protocol (LDAP) for external authentication. An attacker could exploit this vulnerability by entering a 
 specific input on the login page of the affected device. A successful exploit could allow the attacker to gain 
 unauthorized access to the web-based management interface of the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sma-esa-auth-bypass-66kEcxQD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf454769");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx88026");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvx88026");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20798");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:secure_email_and_web_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:content_security_management_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion", "Host/AsyncOS/Cisco Content Security Management Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Content Security Management Appliance (SMA)');

var vuln_ranges = [
  {'min_ver':'0.0', 'fix_ver':'13.0.0.277'},
  {'min_ver':'13.6', 'fix_ver':'13.6.2.090'},
  {'min_ver':'13.8', 'fix_ver':'13.8.1.090'},
  {'min_ver':'14.0', 'fix_ver':'14.0.0.418'},
  {'min_ver':'14.1', 'fix_ver':'14.1.0.250'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvx88026',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
