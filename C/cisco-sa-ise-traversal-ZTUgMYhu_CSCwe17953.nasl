#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176102);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/29");

  script_cve_id("CVE-2023-20167");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe17953");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-traversal-ZTUgMYhu");
  script_xref(name:"IAVA", value:"2023-A-0261");

  script_name(english:"Cisco Identity Services Engine Path Traversal Vulnerability (cisco-sa-ise-traversal-ZTUgMYhu) (CSCwe17953)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Path Traversal Vulnerabilities is affected by
a path traversal vulnerability.

A vulnerability in the web-based management interface of Cisco ISE could allow an authenticated, remote attacker to 
read arbitrary files on the underlying operating system of an affected device. To exploit this vulnerability, an 
attacker must have valid Administrator level privileges on the affected device. This vulnerability is due to improper 
validation of user-supplied input. An attacker could exploit this vulnerability by sending a crafted HTTP request to 
the web application. A successful exploit could allow the attacker to read arbitrary files of specific types from the 
underlying operating system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-traversal-ZTUgMYhu
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?65ba99ac");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe17953");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwe17953");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20167");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');


var vuln_ranges = [
  {'min_ver':'3.1', 'fix_ver':'3.1.0.518'},
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwe17953',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

var version = get_kb_item('Host/Cisco/ISE/version');
var required_patch;
if (version =~ "^3.2.")
  required_patch = 2;
else if (version =~ "^3.1.")
  required_patch = 8;

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
