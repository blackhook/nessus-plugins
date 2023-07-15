#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154344);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/12");

  script_cve_id(
    "CVE-2021-3517",
    "CVE-2021-3522",
    "CVE-2021-35550",
    "CVE-2021-35556",
    "CVE-2021-35559",
    "CVE-2021-35560",
    "CVE-2021-35561",
    "CVE-2021-35564",
    "CVE-2021-35565",
    "CVE-2021-35567",
    "CVE-2021-35578",
    "CVE-2021-35586",
    "CVE-2021-35588",
    "CVE-2021-35603"
  );
  script_xref(name:"IAVA", value:"2021-A-0481-S");

  script_name(english:"Oracle Java SE 1.7.0_321 / 1.8.0_311 / 1.11.0_13 / 1.17.0_1 Multiple Vulnerabilities (October 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business installed on the remote host is prior to 7 Update
321, 8 Update 311, 11 Update 13, or 17 Update 1. It is, therefore, affected by multiple vulnerabilities as referenced
in the October 2021 CPU advisory:

  - Vulnerability in the Java SE product of Oracle Java SE (component: JavaFX (libxml)). The supported version that is 
    affected is Java SE: 8u301. Easily exploitable vulnerability allows unauthenticated attacker with network access 
    via multiple protocols to compromise Java SE. Successful attacks of this vulnerability can result in unauthorized 
    ability to cause a hang or frequently repeatable crash (complete DOS) of Java SE as well as unauthorized update, 
    insert or delete access to some of Java SE accessible data and unauthorized read access to a subset of Java SE 
    accessible data. This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web 
    Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the 
    internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java deployments, 
    typically in servers, that load and run only trusted code (e.g., code installed by an administrator). 
    (CVE-2021-3517)

  - Vulnerability in the Java SE product of Oracle Java SE (component: Deployment). The supported version that is 
    affected is Java SE: 8u301. Difficult to exploit vulnerability allows unauthenticated attacker with network access 
    via multiple protocols to compromise Java SE. Successful attacks require human interaction from a person other than 
    the attacker. Successful attacks of this vulnerability can result in takeover of Java SE. This vulnerability 
    applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java 
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for 
    security. This vulnerability does not apply to Java deployments, typically in servers, that load and run only trusted 
    code (e.g., code installed by an administrator). (CVE-2021-35560)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Libraries). 
    Supported versions that are affected are Java SE: 8u301, 11.0.12, 17; Oracle GraalVM Enterprise Edition: 20.3.3 and 
    21.2.0. Easily exploitable vulnerability allows low privileged attacker with network access via Kerberos to 
    compromise Java SE, Oracle GraalVM Enterprise Edition. Successful attacks require human interaction from a person 
    other than the attacker and while the vulnerability is in Java SE, Oracle GraalVM Enterprise Edition, attacks may 
    significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access 
    to critical data or complete access to all Java SE, Oracle GraalVM Enterprise Edition accessible data. 
    (CVE-2021-35567)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuoct2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2021.html#AppendixJAVA");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2021 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3517");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/22");

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
var dirs;

foreach install (list_uniq(keys(installs)))
{
  ver = install - 'SMB/Java/JRE/';
  if (ver !~ "^[0-9.]+") continue;

  installed_versions = installed_versions + ' & ' + ver;

  # Fixes : (JDK|JRE) 17 Update 1 / 11 Update 13 / 8 Update 311 / 7 Update 321
  if (
    ver_compare(minver:'1.7.0', ver:ver, fix:'1.7.0_321', regexes:{0:"_(\d+)"}, strict:FALSE) < 0 ||
    ver_compare(minver:'1.8.0', ver:ver, fix:'1.8.0_311', regexes:{0:"_(\d+)"}, strict:FALSE) < 0 ||
    ver_compare(minver:'1.11.0', ver:ver, fix:'1.11.0_13', regexes:{0:"_(\d+)"}, strict:FALSE) < 0 ||
    ver_compare(minver:'1.17.0', ver:ver, fix:'1.17.0_1', regexes:{0:"_(\d+)"}, strict:FALSE) < 0
  )
  {

    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.7.0_321 / 1.8.0_311 / 1.11.0_13 / 1.17.0_1\n';
  }
}

# Report if any were found to be vulnerable.
if (info)
{
  var port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (vuln > 1) s = 's of Java are';
  else s = ' of Java is';

  var report =
    '\n' +
    'The following vulnerable instance' + s + ' installed on the\n' +
    'remote host :\n' +
    info;
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else
{
  installed_versions = substr(installed_versions, 3);
  if (' & ' >< installed_versions)
    exit(0, 'The Java '+installed_versions+' installations on the remote host are not affected.');
  else
    audit(AUDIT_INST_VER_NOT_VULN, 'Java', installed_versions);
}

