#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(170203);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id("CVE-2023-21859");
  script_xref(name:"IAVA", value:"2023-A-0039");

  script_name(english:"Oracle Access Manager Elevation of Privilege (Jan 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a Single Sign On (SSO) application installed that is affected by an elevation of privilege vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Access Manager installed on the remote host is affected
by the following vulnerability as noted in the January 2023 CPU advisory:

  - Vulnerability in the Oracle Access Manager product of Oracle Fusion Middleware
    (component: Authentication Engine). The supported version that is affected is
    12.2.1.4.0. Easily exploitable vulnerability allows high privileged attacker
    with logon to the infrastructure where Oracle Access Manager executes to
    compromise Oracle Access Manager. Successful attacks of this vulnerability can
    result in unauthorized access to critical data or complete access to all Oracle
    Access Manager accessible data.

Note that Nessus has not attempted to exploit these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patches according to the January 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21859");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:access_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_access_manager_installed.nbin");
  script_require_keys("installed_sw/Oracle Access Manager");

  exit(0);
}

include('vcf.inc');

var appname = 'Oracle Access Manager';

var app_info = vcf::get_app_info(app:appname);

var constraints = [
  {'min_version': '12.2.1.4', 'fixed_version': '12.2.1.4.221208'}
];
vcf::check_version_and_report(app_info: app_info, constraints: constraints, severity: SECURITY_WARNING);
