#TRUSTED a0b04744cacfa2b4b20ac68b78c9d0b9e11fdc33ed801f5fc83ad72cde03c070ce8c1fbba8a489829306fa8a6d06b8f09037292edeb2d0ac5e2e918272b682a6e6a218fee485c2e5dca931e728bfd8ec1c4b13c42428a6b20ba6b026957cb1f75ace45d4dacb754e1802dfdf73901b103ee0e70976ab71b4ff70680375ffda6b78924755229c7f0c2ca3de4721d6c5bf8fe96f163321c73eef43ce49f319532c724f3100d9e58e785202283e037a19d4f16b16d88f149d5de384fc08fd03ee91f977c1a67d532c26c48a86ba77e5fe440a3bdf64d7c192b67f4e2ddac40c6fe1bbb58b22c097bf2ebdbb2663fb751dfb19fa83c142cfdc6a23a306805b9a6e61f5b8cb8ba51201121a96199a6f89ae67cd4b02c3030a3f79e4922d56409459576f0ea1a52508d03bd565225bedaebd8cfa31b270408739b1be6c510d064c312f4311746e88aaa56256dcbd6a256bba903ad14cd48da9b62b251a7a33e2c8e1696db8b5a3ba0b4900eec371eb431de58e17c2def4f993958824bf9eef62749c45ca06092d9545c3e9aeeb3155e2d329e9ef07d9b2dc364c0885d8b1ff681ce28008f12a0df0be487a78d6eed0781e576ca32c24af9cebd15290056ea310d084950d4223e11c70af2ba09c9bd8990998d3ce733b805e5c317dd5db7b399da8fa79eed6c1dc671f1a5cf3ce622edff696fa79ba768ab38cf23006397b82f6f7deaf
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127123);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/06");

  script_cve_id("CVE-2019-1941");
  script_bugtraq_id(109297);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm10275");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190717-ise-xss");

  script_name(english:"Cisco Identity Services Engine Cross-Site Scripting Vulnerability");
  script_summary(english:"Checks the version of Cisco Identity Services Engine Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web-based management interface of Cisco Identity Services Engine (ISE) could allow an 
unauthenticated, remote attacker to conduct a cross-site scripting (XSS) attack against a user of the web-based 
management interface of an affected device. The vulnerability exists because the web-based management interface 
does not properly validate user-supplied input. An attacker could exploit this vulnerability by persuading a user to 
click a malicious link. A successful exploit could allow the attacker to execute arbitrary script code in the context 
of the affected interface or access sensitive, browser-based information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190717-ise-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42365bf5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm10275");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvm10275");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1941");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);


  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/05");

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

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

vuln_ranges = [
  { 'min_ver' : '0.0',   'fix_ver' : '2.4.0.357' },
  { 'min_ver' : '2.5.0', 'fix_ver' : '2.6.0' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
required_patch = '';
if (product_info['version'] =~ "^2\.4\.0($|[^0-9])") required_patch = '9';

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvm10275',
  'xss'      , TRUE
);

cisco::check_and_report(
  product_info      : product_info,
  workarounds       : workarounds,
  workaround_params : workaround_params,
  reporting         : reporting,
  vuln_ranges       : vuln_ranges,
  required_patch    : required_patch);
