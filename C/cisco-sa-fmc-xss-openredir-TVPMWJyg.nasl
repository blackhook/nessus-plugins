#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154723);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/01");

  script_cve_id("CVE-2021-34763", "CVE-2021-34764");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx32283");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx55664");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fmc-xss-openredir-TVPMWJyg");
  script_xref(name:"IAVA", value:"2021-A-0507");

  script_name(english:"Cisco Firepower Management Center Software Multiple Vulnerabilities (cisco-sa-fmc-xss-openredir-TVPMWJyg)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Firerpower Management Center installed on the remote host is affected by multiple vulnerabilities
as referenced in the cisco-sa-fmc-xss-openredir-TVPMWJyg advisory, as follows:

  - An authenticated, remote attacker can exploit a vulnerability in the web-based management interface by
    persuading a user to click a crafted link, in order to execute arbitrary script code. (CVE-2021-34763)

  - An unauthenticated, remote attacker can exploit a vulnerability in the web interface to redirect a user
    to a malicious web page. This is caused by improper input validation of HTTP request parameters.
    (CE-2021-34764)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-xss-openredir-TVPMWJyg
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1b28819");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx32283");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx55664");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvx32283, CSCvx55664");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34764");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79, 601);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_management_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower_mc/version");

  exit(0);
}

include('vcf.inc');
var app_info = vcf::get_app_info(app:'Cisco Firepower Management Center', kb_ver:'Host/Cisco/firepower_mc/version');

vcf::check_granularity(app_info:app_info, sig_segments:3);
var constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '6.4.0.13' },
  { 'min_version' : '6.5', 'fixed_version' : '6.6.5' },
  { 'min_version' : '6.7', 'fixed_version' : '6.7.0.3' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
