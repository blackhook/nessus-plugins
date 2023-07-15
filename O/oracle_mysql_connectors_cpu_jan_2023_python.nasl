#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170198);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id("CVE-2022-1941");
  script_xref(name:"IAVA", value:"2023-A-0043");

  script_name(english:"Oracle MySQL Python Connector (Jan 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The versions of Python Connector installed on the remote host are affected by a vulnerability as referenced in the
January 2023 CPU advisory. Supported versions that are affected are 8.0.31 and prior. Easily exploitable vulnerability
allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Connectors. Successful
attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash
(complete DOS) of MySQL Connectors.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1941");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_connectors");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_connectors_version_nix.nbin", "mysql_connectors_version_win.nbin");
  script_require_keys("installed_sw/MySQL Connector");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'MySQL Connector');
var product = tolower(app_info['Product']);

vcf::check_granularity(app_info:app_info, sig_segments:3);

if ('python' >!< product)
  audit(AUDIT_PACKAGE_NOT_AFFECTED, product);

var constraints = [
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.32' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
