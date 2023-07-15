#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156887);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/27");

  script_cve_id(
    "CVE-2022-21248",
    "CVE-2022-21271",
    "CVE-2022-21277",
    "CVE-2022-21282",
    "CVE-2022-21283",
    "CVE-2022-21291",
    "CVE-2022-21293",
    "CVE-2022-21294",
    "CVE-2022-21296",
    "CVE-2022-21299",
    "CVE-2022-21305",
    "CVE-2022-21340",
    "CVE-2022-21341",
    "CVE-2022-21349",
    "CVE-2022-21360",
    "CVE-2022-21365",
    "CVE-2022-21366"
  );
  script_xref(name:"IAVA", value:"2022-A-0031-S");

  script_name(english:"Oracle Java SE 1.7.0_331 / 1.8.0_321 / 1.11.0_14 / 1.17.0_2 Multiple Vulnerabilities (January 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business installed on the remote host is affected by multiple
vulnerabilities as referenced in the January 2022 CPU advisory:

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: 2D).
    Supported versions that are affected are Oracle Java SE: 7u321, 8u311; Oracle GraalVM Enterprise Edition: 20.3.4 and
    21.3.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols
    to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result
    in unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM
    Enterprise Edition. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed
    Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from
    the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using APIs in
    the specified Component, e.g., through a web service which supplies data to the APIs. (CVE-2022-21349)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Hotspot). Supported versions that are affected are Oracle Java SE: 7u321, 8u311, 11.0.13, 17.01; Oracle GraalVM
    Enterprise Edition: 20.3.4 and 21.3.0. Easily exploitable vulnerability allows unauthenticated attacker with network
    access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of
    this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Java SE, Oracle
    GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code
    (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs.
    (CVE-2022-21291)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Hotspot). Supported versions that are affected are Oracle Java SE: 7u321, 8u311, 11.0.13, 17.01; Oracle GraalVM
    Enterprise Edition: 20.3.4 and 21.3.0. Easily exploitable vulnerability allows unauthenticated attacker with network
    access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of
    this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Java SE, Oracle
    GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code
    (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs.
    (CVE-2022-21305)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2022.html#AppendixJAVA");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2022 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21291");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

  # Fixes : (JDK|JRE) 17 Update 2 / 11 Update 14 / 8 Update 321 / 7 Update 331
  if (
    ver_compare(minver:'1.7.0', ver:ver, fix:'1.7.0_331', regexes:{0:"_(\d+)"}, strict:FALSE) < 0 ||
    ver_compare(minver:'1.8.0', ver:ver, fix:'1.8.0_321', regexes:{0:"_(\d+)"}, strict:FALSE) < 0 ||
    ver_compare(minver:'1.11.0', ver:ver, fix:'1.11.0_14', regexes:{0:"_(\d+)"}, strict:FALSE) < 0 ||
    ver_compare(minver:'1.17.0', ver:ver, fix:'1.17.0_2', regexes:{0:"_(\d+)"}, strict:FALSE) < 0
  )
  {

    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.7.0_331 / 1.8.0_321 / 1.11.0_14 / 1.17.0_2\n';
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

