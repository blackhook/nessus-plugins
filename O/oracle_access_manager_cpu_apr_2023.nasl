##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(174465);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2019-20916", "CVE-2022-40149", "CVE-2023-22899");
  script_xref(name:"IAVA", value:"2023-A-0210");

  script_name(english:"Oracle Access Manager Multiple Vulnerabilities (Apr 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a Single Sign On (SSO) application installed that is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Access Manager installed on the remote host is missing a security patch from the 
April 2023 CPU Advisory. It is, therefore, affected by multiple vulnerabilities:

  - Vulnerability in the Oracle Access Manager product of Oracle Fusion Middleware (component: Third Party 
    (Jython)). The supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability allows 
    unauthenticated attacker with network access via HTTP to compromise Oracle Access Manager. Successful 
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable 
    crash (complete DOS) of Oracle Access Manager. (CVE-2019-20916)

  - Vulnerability in the Oracle Access Manager product of Oracle Fusion Middleware (component: Build Scripts 
    (Jettison)). The supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability 
    allows unauthenticated attacker with network access via HTTP to compromise Oracle Access Manager. 
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently 
    repeatable crash (complete DOS) of Oracle Access Manager. (CVE-2022-40149)

  - Vulnerability in the Oracle Access Manager product of Oracle Fusion Middleware (component: Third Party 
    (Zip4j)). The supported version that is affected is 12.2.1.4.0. Difficult to exploit vulnerability allows 
    unauthenticated attacker with network access via HTTP to compromise Oracle Access Manager. Successful 
    attacks of this vulnerability can result in unauthorized creation, deletion or modification access to 
    critical data or all Oracle Access Manager accessible data. (CVE-2023-22899)

Note that Nessus has not attempted to exploit these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuApr2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patches according to the April 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20916");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/19");

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

var constraints = [ {'min_version': '12.2.1.4', 'fixed_version': '12.2.1.4.230317'} ];

vcf::check_version_and_report(app_info: app_info, constraints: constraints, severity: SECURITY_WARNING);
