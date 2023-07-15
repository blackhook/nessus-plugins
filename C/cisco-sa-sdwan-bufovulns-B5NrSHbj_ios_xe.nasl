#TRUSTED b2ce6be6288de6e1d827c01ef0938399b8c75715506903bfdf068341cb1ca4df609c6ab6393443a42177ec72a5db3facbeef363c2432ec9c32393f950209f6de4c0b50a4f53ddf4a8b3fbb01cd7cc4c6b7bbd793d7b7c5b7459c755a50aa56612c88f137a467adb7ee3b4f4a0657c6b20d2fed543d8be5238c44a179bb0562ed4af9a93f50fad43f9600849db8cc3656fe9d37f84570016b57961e77d7a4756f071445d34e89cceb9a5c4ab0f7c7c65c420cce376776dd77dd2dd8372ae5dde5de243f7254a54ac60c495e6f4955e1f7bb6fbe0903e002fcdd7f42bd8dc07bd39d610e0f0d29c5adbbd6d498fa3263c7a3081e5be4038b97791edb3311c4ebf3369bba20bccff29366c1b5843ad11195adb115cb298cf4e0d891620f35cc38a84879f0af8834a760eff19d3387f54fc06fff7445e4c77dd1fe1340aafaaca4f4c7750e661d9b832365fee9717bb9502da9102bc6a9f7fe87b9fc83af69fe12c7aa0226a8d2be0af9f950ca65218ec82abe2f94aa073e75617d8840b102f9723fa9726462f726123a3afde1c9a542ff7b5b1e35b6e2eba7c7f65e99cd945522a8fb10ec744e2e890423e93ab45abaefd588572750408bb8e4dfb53254d44032f23fda7d8956795304645428dd547cccaf06898bfcbf82312532da67cb61e1dd2fa17d85fc135259411a66f6e30a46e86cd1c787a96de2eb1819291e87e58511aa
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147962);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/24");

  script_cve_id("CVE-2021-1300", "CVE-2021-1301");
  script_xref(name:"IAVA", value:"2021-A-0045");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi69895");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt11525");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-bufovulns-B5NrSHbj");

  script_name(english:"Cisco IOS XE Buffer Overflow Vulnerabilities (cisco-sa-sdwan-bufovulns-B5NrSHbj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by multiple buffer overflow vulnerabilities
that allow an unauthenticated, remote attacker to execute attacks against an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-bufovulns-B5NrSHbj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f3f0159");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi69895");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt11525");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvi69895, CSCvt11525");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1300");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_ranges = [
  { 'min_ver' : '17.2', 'fix_ver' : '17.2.1' },
  { 'min_ver' : '17.3', 'fix_ver' : '17.3.1' },
  { 'min_ver' : '17.4', 'fix_ver' : '17.4.1' }
];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi69895, CSCvt11525',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
