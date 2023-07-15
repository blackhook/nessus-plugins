#TRUSTED a8d043bebf741184c669730e3931f15cb7203748bdfaad53e82c29c2c0a89bf968565dd0f27169904020b1e600d52a31baff9c1fb7d917233c56fb6fb459a839201bf6c69e1e2daeb451341c294d34ccff93001c5fcc490650ef428c49eb743c1e43b664bace47a71e02bd6ecdd800b5a45e9e700e3ea3b2980a4cf7ca1f1bb20b491ad1c4b671043056cb03e07af45879ea8bca23edc5a6743677b9358994dc73638cf034496e0d0fd2da3e80a260b15d855f649cc85612e83b43632f72605ebc8fa5ebb55bd9120e7061f17fe307d5f772f3c1141f8c7d6874c4fa47066b29a0f725897d4e3f575deb1229c145d3c31cd129446aa3e18ecd5c8e572aeb73892dd52b54914426c761e285f644c50c865daab606fc0abb1730ada32796c212f82df5fabf58eeec40d037dd7de962e27944667a8ed4dfbcb1da56fe72d671a276dae4d571f24dd23151bcbcc67ad2b062ad70c83e9da08863662a8da0ddce5658971cd7516079060dabc04e150544c06756159b6e5d262e5acb8ad4042961c4e9d584c61a232664d1b96832dc5bb7b1f966a2151902d8dcf38499ceaa7fc011962de7e3ee4dc68f96c60b19c7adb3b26df610cb49eb485431fab4c1a8a6391508b6ea54dfcdaf9d03fec8a505c47f479ec465384f374b06da7079889d76bd0d4642bcdfc7e1985c40d9578dcf9fd9dea7b66b8ff871f77d474bfa6eed927bf660
#TRUST-RSA-SHA256 75f96bdd08afab2118c422613fa00eb1f10100c886252427a0cd0f5895e9168740a8322795d02d5a0ff2af955c887630c0c642a0966854db41eb309ac04d1c928d970c3098838547ff2dcc7744676a8c910640abcdcf183cab19eeff9c489a23d5ac9739de36ddf584806cc8da9b4d1dc0ed99fc80995a7d74889bad454f6c3feae04fbca6a5d6a26f7b81cdbd0147f47687258367c3922e8c6a481579b56b211dcf5e5be7206627cca01365bea4f1059c21788dbd163b14f84b6dc2dd76fb8b0ae3b9e2a188d9be4ef400b205d1cb91da41382edf163d7fde69a387a475a97a953e262c5ac5c90b19013c7dc393a1c99a74b9ee4e66f699d7b2dd238bc8b492d480f4990d9ce493f147d9d55cc98c824dd85575cd34c488b1edcf52ba4c807398b0d7f0aa7ffcdc83f69f67edc427531b3420a6ceeb33134c22342100e7f6f5b819dfb59a015dbc3085b8bf44d77afbee055e5d11904fd74258989e0d068054609a508999ec6114bc27d6cb28134dcc865d4e7475f190e541de8db255cd983163dd6f248392e7d3c54690a2135e4541fd733a3f75a72202aa75ffef50dcc83ca85d2458c242b70c6c0436777fa3ce8c0d17e5544a2937981c71f6e3cf05b383a7046227cc91348bdd5c3e42bfc059a9f178361e49e89c144b8f6afade8cddf1d97c571a83d03555f15819bfb48573db6eea66d1e3d6d1b6b49883d46a14175c
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173248);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_cve_id("CVE-2023-20113");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa83035");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vman-csrf-76RDbLEh");
  script_xref(name:"IAVA", value:"2023-A-0157");

  script_name(english:"Cisco SD-WAN vManage Software XSRF (cisco-sa-vman-csrf-76RDbLEh)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the web-based management interface of Cisco SD-WAN vManage Software could allow an
    unauthenticated, remote attacker to conduct a cross-site request forgery (CSRF) attack on an affected
    system. This vulnerability is due to insufficient CSRF protections for the web-based management interface
    on an affected system. An attacker could exploit this vulnerability by persuading a user of the interface
    to click a malicious link. A successful exploit could allow the attacker to perform arbitrary actions with
    the privilege level of the affected user. These actions could include modifying the system configuration
    and deleting accounts. (CVE-2023-20113)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vman-csrf-76RDbLEh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3594abb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa83035");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa83035");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20113");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Cisco/Viptela/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.6.5' },
  { 'min_ver' : '20.8', 'fix_ver' : '20.8.1' },
  { 'min_ver' : '20.9', 'fix_ver' : '20.9.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCwa83035',
  'version'  , product_info['version'],
  'flags', {'xsrf':TRUE},
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
