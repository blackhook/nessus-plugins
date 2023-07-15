#TRUSTED 7f0be432f306b46e4f588129a951a76b44b0e509b523649928ce2844013625b3d37e584bddfd793e2a2c87d7f8bae673616e7e53d4e5719ef33b245af43d19ab6b67b481ccbfe35c6bec56f85bc46b9b43f8753db8c44ced78a31156c4e1c254bce5b9615e129b7a3ecd60159e793b32fc497017593277addaadb7964b9055286d36433dc5ff379e5d875acdbfedea6599cc32177f25eab6299ef76c2d238b4e1d9dcad34109b72bd154eaf1ae54fb0c886874c1743f271e4d6c4ce1fc5b57d589aaa05e9ed6dba6f618f6a6ddd686bedc95e0d83e4af661c9b443cad2bf66726a93f75ffad46bfced7c0aaa071154aa5be1bc6ac16565303579ca0a0a4104f2a5cfc49ee1e704fadc5fed7a2fd989719772aeb21b1330174f9a4287a0003018d8922774d63b23cec7303da8bed798e5defe654ee9b8efbd6568cc0c234e8e2c7589ea458f544659a00b325a2a97615e06169e90240a4db16d416096a11a90ea5353e3c232790d1c65103c9ece2859341ef6cb827b48b7288e8bb5c6cf4c6fcd88ce8003fe9ca7d136406f23b43629e35271e76aec8400b685b64f76daa5d449345c2b178353d49699d964144ed9ef2964876485ff922e895a1aa1a93c585c73cdb5da9a2b102806a92c3a6d619a385fdd3f4666d5cd70de9d5599dfcde1650e699bfd3863cec4faf13f7c0ac07198c4038eb874cacb85b18b3185fd1978abb1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126103);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/06");

  script_cve_id("CVE-2018-15440", "CVE-2018-15463");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm71860");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm79609");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190109-ise-multi-xss");

  script_name(english:"Cisco Identity Services Engine Multiple Cross-Site Scripting Vulnerabilities (cisco-sa-20190109-ise-multi-xss)");
  script_summary(english:"Checks the Cisco Identity Services Engine Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine
Software is affected by multiple cross-site scripting vulnerabilities.
This could  allow an unauthenticated, remote attacker to conduct a 
stored cross-site scripting (XSS) attack or a reflected  cross-site
scripting (XSS) attack against a user of the  web-based management
interface of an affected device. 

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190109-ise-multi-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a6a291e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm71860");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm79609");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCvm71860 and CSCvm79609.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15440");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/21");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Identity Services Engine Software");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

vuln_ranges = [
  { 'min_ver' : '2.2.0', 'fix_ver' : '2.2.0.470' },
  { 'min_ver' : '2.3.0', 'fix_ver' : '2.3.0.298' },
  { 'min_ver' : '2.4.0', 'fix_ver' : '2.4.0.357' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
required_patch = '';
if      (product_info['version'] =~ "^2\.2\.0($|[^0-9])") required_patch = '13';
else if (product_info['version'] =~ "^2\.3\.0($|[^0-9])") required_patch = '6';
else if (product_info['version'] =~ "^2\.4\.0($|[^0-9])") required_patch = '6';

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvm71860, CSCvm79609',
  'fix'      , 'See advisory',
  'xss'      , TRUE
);

# uses required_patch parameters set by above version ranges
cisco::check_and_report(product_info:product_info, reporting:reporting, workarounds:workarounds, workaround_params:workaround_params, vuln_ranges:vuln_ranges, required_patch:required_patch);
