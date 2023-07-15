#TRUSTED 9a704279199a4d23aa301c8a41a404eb9ba2694425c34469185ece88b08eaf7e521095f1dece3c4a5b04ddacec8220e5b519e5b74e6a110cfddf22bfdb64e72e2d92d3b42111c04a48922d2c55e4ff08008e583dfdd741c1ef78bf17373c6315ed5c9301c828c3846f13ffb6440ac36b372563502e531634178dc7c88120cbb14a3c7cb98cdf76214073250ec88229a2a8ab3b9e7cb858f7465546bdbd52df88ab0e2ac51d99e62fe3caad7f24e9d4c175227a9e9a3ffb59116fb7d5728e941e34a36c0d65f08ae42da1f06398640a1292377915fcacae09547abb8f7bd7b060fe2a6d08c7c7243855cbcfd16caa0ecb29fe241ecc4766755b6a437a8c53f583ea9db05e47afc1152a4384e0c9a0e82284c2eee8dd134e325f900fd638e568b98d5453090a29156cf58fef4db02647a9155818a80a2cd3efad969a018a2c97ed04b0d596b47344ff3b6350327e24c78cb5a86106d9ee89d3b1e3d8a484eaa80ad91c6093bcc7ea052acbd4729a1e8059c8fab845d3405ee9e260a5ff0733a28f266592ac0a11ae7bc68b1fb46afe51f5da3253f11c9a2d8239675729d1d76f6888f5c634493d60f178406f854eea3e218b40920fcbb03e00cd0fe370414e1ee9281ba545df0c751db66d59802a3e927c3a87a836a29c17c6d26106edecfbe55fb7a99533c58c189420239f58898d8fc2b487695d7e64c484b3dfcdeb42efd7ff
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126343);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/06");

  script_cve_id("CVE-2018-15459");
  script_bugtraq_id(106707);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi44041");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190123-ise-privilege");

  script_name(english:"Cisco Identity Services Engine Privilege Escalation Vulnerability (cisco-sa-20190123-ise-privilege)");
  script_summary(english:"Checks the version of Cisco Identity Services Engine Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device
is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its
self-reported version, Cisco Identity Services Engine Software is
affected by a privilege escalation vulnerability.  The vulnerability
is due to improper controls on certain pages in the web interface. An
attacker could exploit this vulnerability by authenticating to the
device with an administrator account and sending a crafted HTTP
request. A successful exploit could allow the attacker to create
additional Admin accounts with different user roles. An attacker could
then use these accounts to perform actions within their scope. The
attacker would need valid Admin credentials for the device. This
vulnerability cannot be exploited to add a Super Admin account.

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190123-ise-privilege
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ce85634");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi44041");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvi44041");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15459");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/28");

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
include('lists.inc');

product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

vuln_ranges = [
{ 'min_ver' : '0.0', 'fix_ver' : '2.2.0.470' },
{ 'min_ver' : '2.3.0', 'fix_ver' : '2.3.0.298' },
{ 'min_ver' : '2.4.0', 'fix_ver' : '2.4.0.357' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
required_patch = '';
if (product_info['version'] =~ "^2\.2\.0($|[^0-9])") required_patch = '10';
else if (product_info['version'] =~ "^2\.3\.0($|[^0-9])") required_patch = '5';
else if (product_info['version'] =~ "^2\.4\.0($|[^0-9])") required_patch = '2';

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi44041',
  'fix'      , 'See advisory'
);

# uses required_patch parameters set by above version ranges
cisco::check_and_report(product_info:product_info, reporting:reporting, workarounds:workarounds, workaround_params:workaround_params, vuln_ranges:vuln_ranges, required_patch:required_patch);
