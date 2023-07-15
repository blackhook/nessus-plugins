##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162482);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/25");

  script_cve_id("CVE-2022-20733");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz67073");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ISE-SAML-nuukMPf9");
  script_xref(name:"IAVA", value:"2022-A-0252-S");

  script_name(english:"Cisco Identity Services Engine Authentication Bypass (cisco-sa-ISE-SAML-nuukMPf9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the login page of Cisco Identity Services Engine (ISE) could allow an unauthenticated, remote 
attacker to log in without credentials and access all roles without any restrictions. This vulnerability is due to 
exposed sensitive Security Assertion Markup Language (SAML) metadata. An attacker could exploit this vulnerability by 
using the exposed SAML metadata to bypass authentication to the user portal. A successful exploit could allow the 
attacker to access all roles without any restrictions.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ISE-SAML-nuukMPf9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b10d4992");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz67073");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20733");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}
include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [ {'min_ver':'3.1', 'fix_ver':'3.1.0.518', required_patch:'3'}];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

if (empty_or_null(required_patch))
  audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvz67073',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
