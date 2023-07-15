#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156935);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id("CVE-2021-35587");
  script_xref(name:"IAVA", value:"2022-A-0029");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/12/19");

  script_name(english:"Oracle Access Manager Unknown Vulnerability (Jan 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a Single Sign On (SSO) application installed that is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Access Manager installed on the remote host is affected by the following vulnerability as noted in
the January 2022 CPU advisory

  - Vulnerability in the Oracle Access Manager product of Oracle Fusion Middleware (component: OpenSSO Agent).
    Supported versions that are affected are 11.1.2.3.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Access
    Manager. Successful attacks of this vulnerability can result in takeover of Oracle Access Manager.

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patches according to the January 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35587");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:access_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_access_manager_installed.nbin");
  script_require_keys("installed_sw/Oracle Access Manager");

  exit(0);
}

include('vcf.inc');

var appname = 'Oracle Access Manager';

var app_info = vcf::get_app_info(app:appname);

var constraints = [
  # There is no patch released for 11.1.2.3 so flag all versions and redirect to Oracle
  {'min_version': '11.1.2.3', 'max_version': '11.1.2.3.999999', 'fixed_display': 'See vendor advisory'},
  {'min_version': '12.2.1.3', 'fixed_version': '12.2.1.3.220113'},
  {'min_version': '12.2.1.4', 'fixed_version': '12.2.1.4.220113'}
];
vcf::check_version_and_report(app_info: app_info, constraints: constraints, severity: SECURITY_HOLE);
