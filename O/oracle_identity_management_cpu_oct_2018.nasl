#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118330);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-5645", "CVE-2017-15095", "CVE-2018-3179");
  script_bugtraq_id(97702, 103880, 105636);

  script_name(english:"Oracle Identity Manager Multiple Vulnerabilities (October 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing the October 2018 Critical Patch Update for
Oracle Identity Manager. It is, therefore, affected by multiple
vulnerabilities as described in the October 2018 critical patch
update advisory :

  - An unspecified vulnerability in the Oracle Identity
    Management Suite in the Suite Level Patch Issues
    (Apache Log4j) subcomponent could allow an
    unauthenticated, remote attacker with network access
    via HTTP to compromise Oracle Identity Management Suite.
    (CVE-2017-5645)

  - An unspecified vulnerability in the Oracle Identity
    Manager component of Oracle Fusion Middleware in the
    Advanced Console subcomponent could allow an
    unauthenticated, remote attacker with network access
    via HTTP to compromise Oracle Identity Manager.
    (CVE-2018-3179)

  -  An unspecified vulnerability in the Oracle Identity
     Manager component of Oracle Fusion Middleware in the
     Installer (jackson-databind) subcomponent could allow
     an unauthenticated, remote attacker with network access
     via HTTP to compromise Oracle Identity Manager.
    (CVE-2017-15095)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aca34571");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2018 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5645");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:identity_manager");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_identity_management_installed.nbin");
  script_require_keys("installed_sw/Oracle Identity Manager");

  exit(0);
}

include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");
include("install_func.inc");

product = "Oracle Identity Manager";
install = get_single_install(app_name:product, exit_if_unknown_ver:TRUE);

version = install['version'];
path = install['path'];

fixed = NULL;
report = NULL;

if (version =~ "^11\.1\.2\.3(\.|$)")
{
  fixed = '11.1.2.3.181016';
}
else if (version =~ "^12\.2\.1\.3(\.|$)")
{
  fixed = '12.2.1.3.181016';
}
else audit(AUDIT_INST_PATH_NOT_VULN, product, version, path);

if (!isnull(fixed))
{
  if (ver_compare(ver:version, fix:fixed, strict:FALSE) < 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';
  }
}

if (isnull(report)) audit(AUDIT_INST_PATH_NOT_VULN, product, version, path);

security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
