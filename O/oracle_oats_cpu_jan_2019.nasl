#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121257);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2015-9251",
    "CVE-2016-4000",
    "CVE-2018-0732",
    "CVE-2018-1258",
    "CVE-2018-3303",
    "CVE-2018-3304",
    "CVE-2018-3305",
    "CVE-2018-12023",
    "CVE-2018-14718",
    "CVE-2018-1000300"
  );
  script_bugtraq_id(
    104207,
    104222,
    104442,
    105647,
    105658,
    105659,
    106601,
    106615,
    106618
  );

  script_name(english:"Oracle Application Testing Suite Multiple Vulnerabilities (Jan 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application installed that is affected by 
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Application Testing Suite installed on the
remote host is affected by multiple vulnerabilities : 

  - Enterprise Manager Base Platform Agent Next Gen (Jython) 
    component of Oracle Enterprise Manager Products Suite is easily 
    exploited and can allow an unauthenticated attacker the ability
    to takeover the Enterprise Manager Base Platform. (CVE-2016-4000)

  - Enterprise Manager Base Platform Discovery Framework (OpenSSL) 
    component of Oracle Enterprise Manager Products Suite is easily 
    exploited and can allow an unauthenticated attacker the ability
    to cause a frequent crash (DoS) of the Enterprise Manager Base 
    Platform. (CVE-2018-0732)

  - Enterprise Manager Ops Center Networking (OpenSSL) component of
    Oracle Enterprise Manager Products Suite is easily exploited 
    and can allow an unauthenticated attacker the ability to cause a 
    frequent crash (DoS) of the Enterprise Manager Ops Center
    Platform. (CVE-2018-0732)

  - Oracle Application Testing Suite Load Testing for Web Apps 
    (Spring Framework) component of Oracle Enterprise Manager 
    Products Suite is easily exploited and can allow an 
    unauthenticated attacker the ability to takeover the Enterprise 
    Manager Base Platform. (CVE-2018-1258)

  - Enterprise Manager Base Platform EM Console component is easily 
    exploited by an unauthenticated attacker. Successful attacks 
    can result in unauthorized update, insert, or delete access. 
    (CVE-2018-3303)

  - Oracle Application Testing Suite Load Testing for Web Apps
    component is easily exploited by an unauthenticated attacker. 
    Successful attacks can result in unauthorized update, insert, or 
    delete access and a partial denial of service. (CVE-2018-3304)

  - Oracle Application Testing Suite Load Testing for Web Apps
    component is easily exploited by an unauthenticated attacker. 
    Successful attacks can result in unauthorized update, insert, or 
    delete access and a partial denial of service. (CVE-2018-3305)

  - Enterprise Manager for Virtualization Plug-In Lifecycle 
    (jackson-databind) component of Oracle Enterprise Manager 
    allows an unauthenticated attacker the ability to takeover  
    Enterprise Manager for Virtualization. (CVE-2018-12023)

  - Enterprise Manager for Virtualization Plug-In Lifecycle 
    (jackson-databind) component of Oracle Enterprise Manager 
    allows an unauthenticated attacker the ability to takeover  
    Enterprise Manager for Virtualization. (CVE-2018-14718)

  - Enterprise Manager Ops Center Networking (cURL) component of 
    Oracle Enterprise Manager allows an unauthenticated attacker the 
    ability to takeover Enterprise Manager Ops Center. 
    (CVE-2018-1000300)");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?799b2d05");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2019 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14718");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_testing_suite");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_application_testing_suite_installed.nbin");
  script_require_keys("installed_sw/Oracle Application Testing Suite");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("install_func.inc");

app_name = "Oracle Application Testing Suite";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
ohome = install["Oracle Home"];
subdir = install["path"];
version = install["version"];

fix = NULL;
fix_ver = NULL;

# individual security patches
if (version =~ "^13\.3\.0\.1\.")
{
  fix_ver = "13.3.0.1.301";
  fix = "29172225";
}
else if (version =~ "^13\.2\.0\.1\.")
{
  fix_ver = "13.2.0.1.240";
  fix = "29172233";
}
else if (version =~ "^13\.1\.0\.1\.")
{
  fix_ver = "13.1.0.1.427";
  fix = "29172239";
}
else 
{
  # flag all 12.5.0.3.x 
  fix_ver = "12.5.0.3.999999";
}

# Vulnerble versions that need to patch
if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) == -1)
{
  report =
    '\n  Oracle home    : ' + ohome +
    '\n  Install path   : ' + subdir +
    '\n  Version        : ' + version;
  if (!isnull(fix)) 
  {
    report += 
      '\n  Required patch : ' + fix +
      '\n';
  }
  else
  {
    report += 
      '\n  Upgrade to 13.1.0.1 / 13.2.0.1 / 13.3.0.1 and apply the ' +
      'appropriate patch according to the January 2019 Oracle ' +
      'Critical Patch Update advisory.' +
      '\n';
  }
  security_report_v4(extra:report, port:0, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, subdir);
