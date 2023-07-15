#TRUSTED 450ecbaa7418780218eeb37b82c8082e22c312a9f8764e0e94a1075555d8c1e91c9517a6bedbd61c44076bdaaa5fb4869c647427d30c34c6fbfdf5d11dd333a25078ee3c2771afe1bea4c29f386f7d1641fbb61d36cc17279c4a1408e124557915fb5fc9d9c158e42dea72db9658bdbcb834ab9586c0a0dfb0a57c33f6e5076fcce475ba82c04106cdd9383c89f521f48036f68ef2dad77e4a09fcc65877bb573ca88c484c57a8ac5d5f4701a66771975a570cc12ffea895b6219f569b7e1ac702c637dc18b383e2934537376e3d9a035e294613b48f3646c75eedb0b10c039aa792b27d575e74c086ef12a8425a8ed9c44fb018ea5ce31ebe95c009ce2f4bfa65bf0545fa7ec464ab8c8d6908249b410310a27affe252be50dbedb78f95316736fb29c2dc8a5f34d90812c8e699da0e588a30049b490a0b8b0987c5152d393adc6b36259f5191dcfc118559e07882bab9165154711c7cb96dac9930382ba97ebac4edbfa6018de2cc2f939f3d71241e7570904250a31c5838a51bc29f5afb3ebda0eabf24d1380892c46cc7297db420e7b84ed2f6710db219cc334ca9c66716686b216ebc78fc460358652dce6839994fb58b62baf52bfc35198a926dbd178417dd96999e19911ebfee36288a75c0df39d359373ed761ba2e83f63d65d9d79cce492c83c9fe8c35d80e20ee3570b4a806ce5e16b257eabe4c6f2ebcab03a549
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153950);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/08");

  script_cve_id("CVE-2021-34702");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy86528");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-info-disc-pNXtLhdp");
  script_xref(name:"IAVA", value:"2021-A-0455-S");

  script_name(english:"Cisco Identity Services Engine Sensitive Information Disclosure (cisco-sa-ise-info-disc-pNXtLhdp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Software is affected by a sensitive information 
disclosure vulnerability in the web-based management interface due improper enforcement of administrator privilege 
levels for low-value sensitive data. An authenticated, remote attacker with read-only administrator access to the 
web-based management interface could exploit this vulnerability by browsing to the page that contains the sensitive 
data. A successful exploit could allow the attacker to collect sensitive information regarding the configuration of 
the system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-info-disc-pNXtLhdp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?667259b8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy86528");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy86528");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34702");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  { 'min_ver' : '2.2', 'fix_ver' : '2.3.0'},
  { 'min_ver' : '2.4', 'fix_ver' : '2.6.0.156'},
  { 'min_ver' : '2.7', 'fix_ver' : '2.7.0.356'},
  { 'min_ver' : '3.0', 'fix_ver' : '3.0.0.458'}
];

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
var required_patch = '';
if (product_info['version'] =~ "^2\.6\.0($|[^0-9])")
  required_patch = '11';
else if (product_info['version'] =~ "^2\.7\.0($|[^0-9])")
  required_patch = '5';
else if (product_info['version'] =~ "^3\.0\.0($|[^0-9])")
  required_patch = '4';

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy86528',
  'fix'            , 'See Vendor Advisory',
  'disable_caveat' , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);