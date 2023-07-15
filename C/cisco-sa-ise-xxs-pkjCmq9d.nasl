#TRUSTED af9f01e1055e85e155404ce7d1859146e8d056fb07cccc54f6bbe98be6e2f4b689e71848133ffd8c5b8f46cdb547519d377d9a37fb52322d183a05939d3a2314e7e832edd075841718ae74c62a8c8c99e75e256d3350c7ef6bd3c9933c63d11ed98c4005c0d646d772b38bf46bc0264b637320239f7869c899927fd1526218a9aabfbbcf88553c37b4b895cac23687e5b4ba40b7a74617ace180c974a6cba21e3e2608ccd29dd898670b23d165055150a0a0adcad0ca72fc2b721369033ff55795332c04a611b0e96c6cbe32c7cc69679e62ae00165d722f8ccac8f7297872e581fea50db85ff5c584b7e653e32f6aa5745d0de1583c7664e367174492ce42c22ab7e85cb19fed5cd0cd15d896ff274b33915a34cf7ed1687e020d0d817f02284ea109afd771c78762ed4de46a11dabb0ca6eef50262b40ec5e0c72b05fbef31ad2729f4047f12645cfc695246f52b2981d8a5c30284ee9029a25e78058ae8c65155fca81f22044fe95191f353517de161827f9434689a7a252c37b63fe654a9a799e2c35f6929f3f269adf2687edc8de99b80ba670b9a6cb2ab9335bfb611bc28a7ccd1bae90b28e27c4d4f6fa867e595cd5602d61133a8ab57faf8d60f62b35424e760a1ec1089cd44f71b2c8074295a9161c8a27442684077cdadb754bb33b28e1cad4b8da63817b8b3c60f80c2f17aa15ee051ae381a8a2037ad57378d85
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143220);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/27");

  script_cve_id("CVE-2020-26083");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu84773");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-xxs-pkjCmq9d");
  script_xref(name:"IAVA", value:"2020-A-0500-S");

  script_name(english:"Cisco Identity Services Engine Cross-Site Scripting (cisco-sa-ise-xxs-pkjCmq9d)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Software is affected by a cross-site scripting
(XSS) vulnerability. The vulnerability exists because the web-based management interface does not properly validate
user-supplied input. An authenticated, remote attacker could exploit this vulnerability by injecting malicious code
into specific pages of the interface. A successful exploit could allow the attacker to execute arbitrary script code in
the context of the interface or access sensitive, browser-based information. To exploit this vulnerability, an attacker
would need to have valid administrative credentials.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-xxs-pkjCmq9d
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79ea3a9e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu84773");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu84773");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26083");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

#this vulnerability affected all releases of Cisco ISE.
var vuln_ranges = [
  {'min_ver':'0.0', 'fix_ver':'2.4.0.357'},
  {'min_ver':'2.6', 'fix_ver':'2.6.0.156'},
  {'min_ver':'2.7', 'fix_ver':'2.7.0.356'},
  {'min_ver':'3.0', 'fix_ver':'3.0.0.458'},
];

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
var required_patch = '';

if(product_info['version'] =~ "^2\.4\.0($|[^0-9])")
  var required_patch = '14';
if (product_info['version'] =~ "^2\.6\.0($|[^0-9])")
  var required_patch = '9';
if (product_info['version'] =~ "^2\.7\.0($|[^0-9])")
  var required_patch = '3';
if (product_info['version'] =~ "^3\.0\.0($|[^0-9])")
  var required_patch = '3';


var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu84773',
  'fix'      , 'See vendor advisory',
  'xss'      , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);