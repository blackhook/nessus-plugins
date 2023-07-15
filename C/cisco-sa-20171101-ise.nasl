#TRUSTED 34aff4649d53de576158014056adee608471f24b2029a36d95361c68370cb291e295b4894191051b12a538af0c1aebea12cf303725923ace4503549da946917859f6b99db52b4ec57c200c7c41aba24e4289a67f904537fca56e98c9696a002cf0d5dccfeb1fce959028d0071a482e818490209191ac2d6c959ad53e43f5d70169b3eb508d377f5e07b605330cf54190bffc84a57b400e828abe8c9bbe260fabe26eb6a97a01975ca5c64ce5ad6720cb3086085aec21e52460ecda5e0bc8705def62afc18378b79c5e7488e55fa51de7c5450ddfcd204d62f9b5e18d033be7a504860c6c4556795f584cdd42d255e1aaf83480e159624fedf65383cdfdf38676a64fe06bff8fbad5d4f4d4fa3112535824a66435ace6049a9a39b533f7eaf9e8be84efb253ccab2e473bb8039240e0370cd04dab1e5f9192b929fe2d2a6d3bf312782798813ea4079b0d0164b396f25e19534331bb0718b3d1998ab04c363af449ba6ef13cc074d8d60992f4e409ed04cda17813baf8162d9dbe4e477b79cc2eeec80eb1b5b660382eeb915b6c06678bd78bb5c1fcdef8bbfd2047dd73239e5d6455897ee100073f2cdc52796ff8038aab0954eef8f1e3eee3037db0710dc7cbdcb66e9385fcba5037dc69819482c3f8949216bbac5967fbcd5b682defeeebc876a07960c69264f8ca7524516492588e41c66f2df0275d2bc6557e2eb1c94df1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104480);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/06");

  script_cve_id("CVE-2017-12261");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve74916");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171101-ise");

  script_name(english:"Cisco Identity Services Engine Privilege Escalation Vulnerability");
  script_summary(english:"Checks the Cisco Identity Services Engine Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Identity Services
Engine Software is affected by a privilege escalation vulnerability.
Please see the included Cisco BID and the Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171101-ise
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?65b58def");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve74916");

  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCve74916.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12261");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Identity Services Engine Software");

vuln_ranges = [
  { 'min_ver' : '1.3', 'fix_ver' : '1.3.0.876' },
  { 'min_ver' : '1.4', 'fix_ver' : '1.4.0.253' },
  { 'min_ver' : '2.0.0', 'fix_ver' : '2.0.0.306' },
  { 'min_ver' : '2.0.1', 'fix_ver' : '2.0.1.130' },
  { 'min_ver' : '2.1.0', 'fix_ver' : '2.1.0.474' },
  { 'min_ver' : '2.2.0', 'fix_ver' : '2.2.0.470' },
  { 'min_ver' : '2.3.0', 'fix_ver' : '2.3.0.298' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
required_patch = '';
if      (product_info['version'] =~ "^2\.2\.0($|[^0-9])") required_patch = '2';
else if (product_info['version'] =~ "^2\.1\.0($|[^0-9])") required_patch = '5';
else if (product_info['version'] =~ "^2\.0\.1($|[^0-9])") required_patch = '5';
else if (product_info['version'] =~ "^2\.0($|[^0-9])")    required_patch = '6';
else if (product_info['version'] =~ "^1\.4($|[^0-9])")    required_patch = '12';
else if (product_info['version'] =~ "^1\.3($|[^0-9])")    required_patch = '12';

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCve74916",
  'fix'      , 'See advisory'
);

# uses required_patch parameters set by above version ranges
cisco::check_and_report(product_info:product_info, reporting:reporting, workarounds:workarounds, workaround_params:workaround_params, vuln_ranges:vuln_ranges, required_patch:required_patch);
