#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133002);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2020-2728", "CVE-2020-2729");
  script_xref(name:"IAVA", value:"2020-A-0019");

  script_name(english:"Oracle Identity Manager Multiple Vulnerabilities (Jan 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a remote
security vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing the January 2020 Critical Patch Update for
Oracle Identity Manager. It is, therefore, affected by multiple vulnerabilities:

 - Easily exploitable vulnerability allows an unauthenticated remote attacker to compromise Identity
   Manager. Successful attacks of this vulnerability can result in unauthorized access to critical
   data or complete access to all Identity Manager accessible data. (CVE-2020-2728)

 - Easily exploitable vulnerability allows a low privileged remote attacker to compromise Identity
   Manager. Successful attacks of this vulnerability can result in unauthorized update, insert
   or delete access to some of Identity Manager accessible data as well as unauthorized read access
   to a subset of Identity Manager accessible data. (CVE-2020-2729)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2020 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2729");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-2728");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:identity_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_identity_management_installed.nbin");
  script_require_keys("installed_sw/Oracle Identity Manager");

  exit(0);
}
include('vcf.inc');

appname = 'Oracle Identity Manager';

app_info = vcf::get_app_info(app:appname);
 
constraints = [
  {'min_version': '11.1.2.3', 'fixed_version': '11.1.2.3.190922'},
  {'min_version': '12.2.1.3', 'fixed_version': '12.2.1.3.200108'}
];
vcf::check_version_and_report(app_info: app_info, constraints: constraints, severity: SECURITY_WARNING);
