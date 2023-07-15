#TRUSTED 14c98b5514009b2395ed65017a9aa2678ddaf8f18bf849ac512a8931fed1f8dabc7e761a0a189f4ab12ccdb96301fb70d10411fd37ad08ccea5ee8d194676c0e1eeefd2c41d0c4d4498adba346a8d1f290e512819eba0a10a433ff5e40144f597f8fd43d6d46a8654a58cd2d950dea21ce7273bfcb34ceef742f13875c01c92eb114165099d618a416c7702ed052e99006bed2d09a4bd6f3d1062010eb8636b03aa0ae491484d3ad81d4189a8496d982b7daa68784c3a6300503676fa7168486219e996e2a04d595da925d3abf042c4a95344eb407b331825c71a5f2a2a2e9991b17df989e470fd57331b01af950ef85c83eb693f4c78d506598dec43cb0dc5169635dca10e2ffdeb44f514a84db3c47ec8c8a534b7ae8c95ad5101636c24951d9934841dd484e48fd2860b48f032669702be6ca0bb93ae25cafa655a2eaba479a6e7db839ab46187973feded98b92196336681e3c25e13fe23a35c474b6785b294242437f150a21cc0852a5a9e53e15186ca6e3128e9d40f9a16cd0a5a496c0d188e126d535434babf0f756cd546d2b74ab8cbcecaf8923126f8cfa0975c6d3b157185e735d9fd5784c1b16e5007b5a7b923e7762a04e4f166ded4ac9954853494b247061112ac3c5f64f41f3fc90fa67ad990a5441e679a81162e6a1d7ea4861aeffaf515075f170a26ab2114015bac1af6b1670807f30618ee3b2ff69581d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129814);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/06");

  script_cve_id("CVE-2019-12631");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq54153");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-ise-xss");

  script_name(english:"Cisco Identity Services Engine Cross-Site Scripting Vulnerability");
  script_summary(english:"Checks the version of Cisco Identity Services Engine Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web-based guest portal of Cisco Identity Services Engine (ISE) could allow an unauthenticated,
remote attacker to conduct a cross-site scripting (XSS) attack against a user of the web-based management interface.
The vulnerability is due to insufficient validation of user-supplied input that is processed by the web-based
management interface. An attacker could exploit this vulnerability by persuading a user to click a crafted link.
A successful exploit could allow the attacker to execute arbitrary script code in the context of the interface or
access sensitive browser-based information.
Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-ise-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14b14bd7");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq54153");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq54153");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12631");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '2.4.0.357' },
  { 'min_ver' : '2.6', 'fix_ver' : '2.6.0.156' }
];

# Patch check is taken care of in ccf.
if (product_info['version'] =~ '^2\\.6') required_patch = '3';
else required_patch = '10';

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq54153',
  'fix'      , 'See advisory',
  'xss'      , TRUE
);

# uses required_patch parameters set by above version ranges
cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  workaround_params:workaround_params,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
