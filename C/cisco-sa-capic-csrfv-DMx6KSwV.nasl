#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171879);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/06");

  script_cve_id("CVE-2023-20011");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd15559");
  script_xref(name:"CISCO-SA", value:"cisco-sa-capic-csrfv-DMx6KSwV");
  script_xref(name:"IAVA", value:"2023-A-0116");

  script_name(english:"Cisco Application Policy Infrastructure Controller XSRF (cisco-sa-capic-csrfv-DMx6KSwV)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Application Policy Infrastructure Controller is affected by a cross-site
request forgery (XSRF) vulnerability. An unauthenticated, remote attacker could exploit this vulnerability by
persuading a user of the interface to click a malicious link resulting in the attacker being able to perform arbitrary
actions with the privilege of the user.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-capic-csrfv-DMx6KSwV
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4cbeaee2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd15559");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwd15559");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20011");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_policy_infrastructure_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_apic_version.nbin");
  script_require_keys("installed_sw/Cisco APIC Software");

  exit(0);
}

include('ccf.inc');
include('http.inc');

var port = get_http_port(default:443);
var product_info = cisco::get_product_info(name:'Cisco APIC Software', port:port);

var vuln_ranges = [
  {'min_ver': '4.2(6)', 'fix_ver': '5.2(7g)'},
  {'min_ver': '6.0', 'fix_ver': '6.0(2e)'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'flags'         , {'xsrf':TRUE},
  'bug_id'        , 'CSCwd15559',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
