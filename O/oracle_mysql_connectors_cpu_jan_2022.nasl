#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156889);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id("CVE-2021-3712", "CVE-2022-21363");
  script_xref(name:"IAVA", value:"2022-A-0030");

  script_name(english:"Oracle MySQL Connectors (January 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 8.0.27 and prior versions of MySQL Connectors installed on the remote host are affected by multiple 
vulnerabilities as referenced in the January 2022 CPU advisory:

  - Vulnerability in the MySQL Connectors product of Oracle MySQL (component: Connector/C++ (OpenSSL)). Supported 
    versions that are affected are 8.0.27 and prior. Difficult to exploit vulnerability allows unauthenticated 
    attacker with network access via multiple protocols to compromise MySQL Connectors. Successful attacks of this 
    vulnerability can result in unauthorized access to critical data or complete access to all MySQL Connectors 
    accessible data and unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of 
    MySQL Connectors. (CVE-2021-3712)

  - Vulnerability in the MySQL Connectors product of Oracle MySQL (component: Connector/J). Supported versions that 
    are affected are 8.0.27 and prior. Difficult to exploit vulnerability allows high privileged attacker with network
    access via multiple protocols to compromise MySQL Connectors. Successful attacks of this vulnerability can result 
    in takeover of MySQL Connectors. (CVE-2022-21363)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2022.html#AppendixMSQL");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21363");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3712");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_connectors");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_connectors_version_nix.nbin", "mysql_connectors_version_win.nbin");
  script_require_keys("installed_sw/MySQL Connector");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'MySQL Connector');
var product = tolower(app_info['Product']);

vcf::check_granularity(app_info:app_info, sig_segments:3);

if ('java' >!< product && 'odbc' >!< product && 'cpp' >!< product && 'c++' >!< product)
  audit(AUDIT_PACKAGE_NOT_AFFECTED, product);

var constraints = [{'min_version': '8.0.0', 'fixed_version': '8.0.28'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

