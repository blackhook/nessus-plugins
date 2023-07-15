#TRUSTED 7da8d7ccbfe6e5ec237f9da08c6365014ebc9a3ae240edb9c94b9a14f28e8b803f974d3d9e048e8e9ec2a2f8a2322ddd7361954d671a47a9be1b22319254b63eb5cf1e3761cf107117b2a2847a19672184f6628423a72b94e6383083df85821e2362391dc04938c14c92d36bc396760f161e50b9e063265cb9211375b4b53170d4863378ec9b7b40822605f1c8d6b3e89209a0e0ce6ef84ceb2379a769dfca933b34b4219d0fa4b81f68ea392e6e65fcb5ef40bf91e49aec5a0530187a38103fcc56604fed983330e9f946c4141b275ae90bf8bcefe178850ae67dfd5374233320ffa6c2c591cc8e20bacd90e2a55a3c14e81091336dd2675e98fa0cdb08501a4c6d8130e2e3e504f35ba9509d30aae5fe69aa4e60d26f166e9492403a311efabe4fb1d6c7bd316d0870a41db99009275cc2fdc0cf3bfd789167ff8693a6a172068842544fa42526814881ad70b1a1dc4ee7fa58c1739be56a76bce77b9c5c6b941cfeb52c2105493cdbb4c7441bf9e9be7a6c1158f309f41df3f5f43fe99f42514bd7857783f0735b8575daea5c35dc3c6ce3a39edd9fd19249943f2336d9fb430e31161e3d5dc84ed2400cce52c25a00323af8ed5b5125c7eea959fd70077329bb515863b14e6ed582714463df9ef38c22afe9880fce92c1c7ba7f3f8f66f54027fba83e66e4003d1e534e9822367b3407db3a36e25ad37fde07afdead3902
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138440);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/20");

  script_cve_id("CVE-2019-1797");
  script_bugtraq_id(107998);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj06910");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190417-wlc-csrf");

  script_name(english:"Cisco Wireless LAN Controller Software Cross-Site Request Forgery (cisco-sa-20190417-wlc-csrf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, a Cross-site request forgery (XSRF) vulnerability
 exists in Cisco Wireless LAN Controller due to insufficient XSRF protections for the web-based 
 management interface. An unauthenticated, remote attacker can exploit this, by convincing a user 
 to click a specially crafted URL, to perform arbitrary actions on the device with the privileges 
 of the user.
 
the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190417-wlc-csrf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1483a710");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj06910");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvj06910");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1797");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_(wlc)");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '8.3.150.0'},
  {'min_ver' : '8.4', 'fix_ver' : '8.5.135.0'},
  {'min_ver' : '8.6', 'fix_ver' : '8.8.100.0'}
];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvj06910',
  'xsrf' , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
