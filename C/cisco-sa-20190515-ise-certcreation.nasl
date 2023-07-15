#TRUSTED 2d541db8e51d71c8e6c07d81cf93cf7b32eaeacc0a7dfa9538a5161e0a0cb94493f50b35dd765cd27360db4644f5d29fbbce75235d0ae4ba8d7bba3ecc945fbf640e86fd78089e1e229adfb20ad966ff09646aa50f83f505f131a1c15b2cf7710216988fe5f1f688bc2ee58afccd1002f684caec6cee11987dfb1fa1c728f87bf16fa39af91f68c4e9d4868d253f9cb7721d94ebf475157856648c267278c17ac01e8609a1481af95ca56ba4c53d1062057310a6c2bedb0b3ed1d488ccac4767396228a38d2bf180f7affed4b83f07dd5b2f02c633799fee0e1fe799616e71f24c5c96ea4b6f22cbf5686284ad2837510d46f5c9570788aacceddae7853863c1917cdc06e5a0ab789ad91eedf56b0b371a0263df987afe222a485e99dddc00fa12d6528ee9927316d3779e8c564fdb50cdad9370a01586b3ac3a2035716333c33b7f7438d5b59b7f65949896daf3238ad9663204a969d7ac7c880b37bdc6635afcbe8dcb0fa8982b64868341500fdbda340de4e17f959da75f3193a7167323deaf8c25ca5741ea283b9a0144d437a8d6d280453f40b1fa0d466658d5871685c9fbec039a1d10fbdc643f7796d27a8836ebe7f2e767c4bb0bda64f3cf8d9209d5a6900a3ae22f64a7c6a9701fe15a2c8d127d47753e686bed8c71815b1daabb7c6301a7f298b0df11b17582447dadda3971ef806b1b62c3f8e874a75b043a2ad9
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(128684);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/06");

  script_cve_id("CVE-2019-1851");
  script_bugtraq_id(108356);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm81230");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-ise-certcreation");

  script_name(english:"Cisco Identity Services Engine Arbitrary Client Certificate Creation Vulnerability");
  script_summary(english:"Checks the version of Cisco Identity Services Engine Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the External RESTful Services (ERS) API of the
 Cisco Identity Services Engine (ISE) could allow an authenticated,
 remote attacker to generate arbitrary certificates signed by the
 InternalCertificate Authority (CA) Services on ISE. This
 vulnerability is due to an incorrect implementation of role-based
 access control (RBAC). An attacker could exploit this vulnerability
 by crafting a specific HTTP request with administrative credentials.
 A successful exploit could allow the attacker to generate a
 certificate that is signed and trusted by the ISE CA with arbitrary
 attributes. The attacker could use this certificate to access other
 networks or assets that are protected by certificate authentication.

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-ise-certcreation
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?980cfdbf");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm81230");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvm81230");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1851");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(285);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/11");

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
include('lists.inc');

product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');
if (report_paranoia < 2) audit(AUDIT_PARANOID);

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
if (product_info['version'] =~ "^2\.2\.0($|[^0-9])") required_patch = '15';
else if (product_info['version'] =~ "^2\.3\.0($|[^0-9])") required_patch = '7';
else if (product_info['version'] =~ "^2\.4\.0($|[^0-9])") required_patch = '8';

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvm81230',
  'fix'      , 'See advisory'
);

# uses required_patch parameters set by above version ranges
cisco::check_and_report(
    product_info:product_info,
    reporting:reporting,
    workarounds:workarounds,
    workaround_params:workaround_params,
    vuln_ranges:vuln_ranges,
    required_patch:required_patch);
