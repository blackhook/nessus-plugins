#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166917);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/07");

  script_cve_id("CVE-2022-20963");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb75959");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-stor-xss-kpRBWXY");
  script_xref(name:"IAVA", value:"2022-A-0462");

  script_name(english:"Cisco Identity Services Engine Stored XSS (cisco-sa-ise-stor-xss-kpRBWXY)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Stored is affected by a cross-site scripting
vulnerability. This could allow an authenticated, remote attacker to conduct a cross-site scripting (XSS) attack 
against a user of the web-based management interface of an affected device. This vulnerability is due to insufficient 
validation of user-supplied input by the web-based management interface of an affected device. An attacker could 
exploit this vulnerability by injecting malicious code into specific pages of the interface. A successful exploit could 
allow the attacker to execute arbitrary script code in the context of the affected interface or access sensitive, 
browser-based information. To exploit this vulnerability, the attacker would need valid credentials to access the 
web-based management interface of an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-stor-xss-kpRBWXY
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2a73a91");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb75959");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwb75959");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20963");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(87);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
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

var vuln_ranges = [ 
  {'min_ver':'0.0', 'fix_ver':'2.7.0.356', required_patch:'8'},
  {'min_ver':'3.0', 'fix_ver':'3.0.0.458', required_patch:'7'},
  {'min_ver':'3.1', 'fix_ver':'3.1.0.518', required_patch:'4'}];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

if (empty_or_null(required_patch))
  audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'flags'         , {'xss':TRUE},
  'bug_id'        , 'CSCwb75959',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
