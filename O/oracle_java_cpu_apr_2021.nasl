#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148960);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2021-2161", "CVE-2021-2163");
  script_xref(name:"IAVA", value:"2021-A-0195");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Java SE 1.7.0_301 / 1.8.0_291 / 1.11.0_11 / 1.16.0_1 Multiple Vulnerabilities (Apr 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business installed on the remote host is prior to 7 Update
301, 8 Update 291, 11 Update 11, or 16 Update 1. It is, therefore, affected by multiple vulnerabilities as referenced
in the April 2021 CPU advisory:

  - A vulnerability in Java SE, SE Embedded and Oracle GraalVM Enterprise Edition allows unauthenticated remote attacker
    to compromise the system which can result in an unauthorized creation, deletion or modification access to critical
    data. (CVE-2021-2161)

  - A vulnerability in Java SE, SE Embedded and Oracle GraalVM Enterprise Edition allows unauthenticated remote attacker
    with a human interaction from a person other than the attacker to compromise the system which can result in an 
    unauthorized creation, deletion or modification access to critical data. (CVE-2021-2163)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2021.html#AppendixJAVA");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2021 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2161");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed.nasl");
  script_require_keys("SMB/Java/JRE/Installed");

  exit(0);
}

# Check each installed JRE.
var installs = get_kb_list_or_exit('SMB/Java/JRE/*');

var info = '';
var vuln = 0;
var installed_versions = '';
var install;

foreach install (list_uniq(keys(installs)))
{
  ver = install - 'SMB/Java/JRE/';
  if (ver !~ "^[0-9.]+") continue;

  installed_versions = installed_versions + ' & ' + ver;

  # Fixes : (JDK|JRE) 16 Update 1 / 11 Update 11 / 8 Update 291 / 7 Update 301
  if (
    ver_compare(minver:'1.7.0', ver:ver, fix:'1.7.0_301', regexes:{0:"_(\d+)"}, strict:FALSE) < 0 ||
    ver_compare(minver:'1.8.0', ver:ver, fix:'1.8.0_291', regexes:{0:"_(\d+)"}, strict:FALSE) < 0 ||
    ver_compare(minver:'1.11.0', ver:ver, fix:'1.11.0_11', regexes:{0:"_(\d+)"}, strict:FALSE) < 0 ||
    ver_compare(minver:'1.16.0', ver:ver, fix:'1.16.0_1', regexes:{0:"_(\d+)"}, strict:FALSE) < 0
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);
    var dir;

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.7.0_301 / 1.8.0_291 / 1.11.0_11 / 1.16.0_1\n';
  }
}

# Report if any were found to be vulnerable.
if (info)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (vuln > 1) s = 's of Java are';
  else s = ' of Java is';

  report =
    '\n' +
    'The following vulnerable instance' + s + ' installed on the\n' +
    'remote host :\n' +
    info;
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else
{
  installed_versions = substr(installed_versions, 3);
  if (' & ' >< installed_versions)
    exit(0, 'The Java '+installed_versions+' installations on the remote host are not affected.');
  else
    audit(AUDIT_INST_VER_NOT_VULN, 'Java', installed_versions);
}

