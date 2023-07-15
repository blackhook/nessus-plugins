#TRUSTED 62c101360a2521015bda17d407f2c5a2a066a7c4b8bc585f0d8b934b55469892c844cccd02df6a60dfb6f356de190a2cbcf98ab9a6b3603cb6443e8c4b4c064ab4fe7a9f046ea7548926cd660581d41e326fb4f7059002be6dfddadc06c3b296126b420f2aca31894752fa8d7430f272920b8296a8c94552deb958e10e34fa225c279a9020f707e44433ee77835473acc3d449524b7adf92d0a4f10de3a6000979814774d86f5f6962763779de598d2ea66997fdc51c540d644b92ad344336899d50c925a017c263652701f631e0b48e6ad4992290ad21717ec0e0d02a2ed7109e2652ee13fa843c3fa4eb2c64a501fe3d8e6a8e8d3ed46cef08d63f6cb56effd2442e11a913ca4d6ff101271230866e166fed063cabd51b67f2a376cf6c7b1a46c91daf4eae6084a36d706ce160e8e43e600093ce0fd2c54451cbce2a9bf81cc35bd2375c7cb5742710ef5f9968acf83e37b4542a7ca5a77e48b06317e9200888ce3e8054ccf7d904b22e6ca2e71b617745917edcd528a7e45f1844e1ddaa7081ac8bbb557f94a781b5b0ab5c8a4b39d00a31f43f110fd1a123b23cb03815b14e49ea2a05978bf86ec70318255cbb2d9beea85d5d0e5f6828000767060ca48058536d76d005f0ed5219fe1f330d17a67e3df001c2f4609936e0717271fb7a6cc29abcf97181e24b4948f2bf321cd5e2f5acfa43cd432bf687e4df3291e93573
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130259);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/20");

  script_cve_id("CVE-2019-15266");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq59683");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191016-wlc-pathtrav");

  script_name(english:"Cisco Wireless LAN Controller Path Traversal Vulnerability");
  script_summary(english:"Checks version of Cisco Wireless LAN Controller");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Wireless LAN Controller (WLC) is affected by a directory traversal
vulnerability due to improper sanitization of user-supplied input in command-line parameters that describe file names.
An authenticated, local attacker can exploit this to view system files that should be restricted.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191016-wlc-pathtrav
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2da8949");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq59683");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq59683");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15266");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_(wlc)");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");
  exit(0); 
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

vuln_ranges = [ #  8.8 will get Maintainence Version in the near future
                { 'min_ver' : '8.4', 'fix_ver' : '8.5.160.0'},
                { 'min_ver' : '8.6', 'fix_ver' : '8.10'}
              ];

reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_NOTE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvq59683',
'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
