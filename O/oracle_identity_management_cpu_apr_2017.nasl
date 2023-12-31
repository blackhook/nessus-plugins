#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99470);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-3553");

  script_name(english:"Oracle Identity Manager Rules Engine Vulnerability (April 2017 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by an
unspecified vulnerability that impacts confidentiality, integrity, and
availability.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing the April 2017 Critical Patch Update for
Oracle Identity Manager. It is, therefore, affected by an unspecified
vulnerability in the Rules Engine subcomponent that allows an
authenticated, remote attacker to impact confidentiality, integrity,
and availability.");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?623d2c22");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2017 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3553");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:identity_manager");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  fixed = '11.1.2.3.170418';

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
