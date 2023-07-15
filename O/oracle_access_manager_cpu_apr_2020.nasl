#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135697);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-2740", "CVE-2020-2745", "CVE-2020-2747");
  script_xref(name:"IAVA", value:"2020-A-0153");

  script_name(english:"Oracle Access Manager Multiple Vulnerabilities (Apr 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a Single Sign On (SSO) application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Access Manager installed on the remote host is affected by the following vulnerabilities as noted in
the April 2020 CPU advisory :

  - An unspecified vulnerability exists in the Authentication Engine component of Oracle Fusion Middleware
    subcomponent Oracle Access Manager.  An authenticated, remote attacker can exploit this, via HTTP, to
    update, insert, or delete some of Oracle Access Manager accessible data, as well as unauthorized read to a
    subset of Oracle Access Manager accessible data. (CVE-2020-2740)
  
  - An unspecified vulnerability exists in the Federation component of Oracle Fusion Middleware subcomponent
    Oracle Access Manager.  An unauthenticated, remote attacker can exploit this, via HTTP, to cause a partial
    denial of service (DoS) of Oracle Access Manager. (CVE-2020-2745)
  
  - An unspecified vulnerability exists in the SSO Engine component of Oracle Fusion Middleware subcomponent
    Oracle Access Manager.  An authenticated, remote attacker can exploit this, via HTTP, to update, insert,
    or delete some of Oracle Access Manager accessible data, as well as unauthorized read to a subset of
    Oracle Access Manager accessible data. (CVE-2020-2747)
  
Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patches according to the April 2020 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2747");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_access_manager_installed.nbin");
  script_require_keys("installed_sw/Oracle Access Manager");

  exit(0);
}

include('vcf.inc');

appname = 'Oracle Access Manager';

app_info = vcf::get_app_info(app:appname);
 
constraints = [
  {'min_version': '11.1.2.3', 'fixed_version': '11.1.2.3.191004'},
  {'min_version': '12.2.1.3', 'fixed_version': '12.2.1.3.191201'}
];
vcf::check_version_and_report(app_info: app_info, constraints: constraints, severity: SECURITY_WARNING);
