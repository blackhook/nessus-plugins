#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135592);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2019-18197",
    "CVE-2020-2754",
    "CVE-2020-2755",
    "CVE-2020-2756",
    "CVE-2020-2757",
    "CVE-2020-2764",
    "CVE-2020-2767",
    "CVE-2020-2773",
    "CVE-2020-2778",
    "CVE-2020-2781",
    "CVE-2020-2800",
    "CVE-2020-2803",
    "CVE-2020-2805",
    "CVE-2020-2816",
    "CVE-2020-2830"
  );
  script_xref(name:"IAVA", value:"2020-A-0134-S");

  script_name(english:"Oracle Java SE 1.7.0_261 / 1.8.0_251 / 1.11.0_7 / 1.14.0_1 Multiple Vulnerabilities (Apr 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business installed on the remote host is prior to 7 Update
261, 8 Update 251, 11 Update 7, or 14 Update 1. It is, therefore, affected by multiple vulnerabilities related to the
following components :

  - Oracle Java SE and Java SE Embedded are prone to a buffer overflow attack, over 'Multiple' protocol.
    This issue affects the 'JavaFX (libxslt)' component. Successful attacks of this vulnerability allow 
    unauthenticated attacker with network access to takeover of Java SE. (CVE-2019-18197)

  - Oracle Java SE and Java SE Embedded are prone to partial denial of service (partial DOS) vulnerability.
    An unauthenticated remote attacker can exploit this over 'Multiple' protocol. This issue affects the
    'Scripting' component. (CVE-2020-2754, CVE-2020-2755)

  - Oracle Java SE and Java SE Embedded are prone to partial denial of service (partial DOS) vulnerability.
    An unauthenticated remote attacker can exploit this over 'Multiple' protocol. This issue affects the
    'Serialization' component. (CVE-2020-2756, CVE-2020-2757)

  - Oracle Java SE prone to unauthorized read access vulnerability. An unauthenticated remote attacker can
    exploit this over 'Multiple' protocol can result in unauthorized read access to a subset of Java SE
    accessible data. This issue affects the 'Advanced Management Console' component. (CVE-2020-2764)

  - Oracle Java SE and Java SE Embedded are prone to unauthorized write/read access vulnerability. An
    unauthenticated remote attacker over 'HTTPS' can read, update, insert or delete access to some of Java SE
    accessible data. This issue affects the 'JSSE' component. (CVE-2020-2767)

  - Oracle Java SE and Java SE Embedded are prone to partial denial of service (partial DOS) vulnerability.
    An unauthenticated remote attacker can exploit this over 'Multiple' protocol. This issue affects the
    'Scripting' component. (CVE-2020-2773)

It is also affected by other vulnerabilities; please see vendor advisories for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2020.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 14 Update 1 , 11 Update 7, 8 Update 251 , 7 Update 261 or later.
If necessary, remove any affected versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2800");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-2805");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed.nasl");
  script_require_keys("SMB/Java/JRE/Installed");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

# Check each installed JRE.
installs = get_kb_list_or_exit("SMB/Java/JRE/*");

info = "";
vuln = 0;
installed_versions = "";

foreach install (list_uniq(keys(installs)))
{
  ver = install - "SMB/Java/JRE/";
  if (ver !~ "^[0-9.]+") continue;

  installed_versions = installed_versions + " & " + ver;

  # Fixes : (JDK|JRE) 13 Update 2 / 11 Update 6 / 8 Update 214 / 7 Update 251 
  if (
    ver_compare(minver:"1.7.0", ver:ver, fix:"1.7.0_261", regexes:{0:"_(\d+)"}, strict:FALSE) < 0 ||
    ver_compare(minver:"1.8.0", ver:ver, fix:"1.8.0_251", regexes:{0:"_(\d+)"}, strict:FALSE) < 0 ||
    ver_compare(minver:"1.11.0", ver:ver, fix:"1.11.0_7", regexes:{0:"_(\d+)"}, strict:FALSE) < 0 ||
    ver_compare(minver:"1.13.0", ver:ver, fix:"1.14.0_1", regexes:{0:"_(\d+)"}, strict:FALSE) < 0 

  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.7.0_261 / 1.8.0_251 / 1.11.0_7 / 1.14.0_1\n';
  }
}

# Report if any were found to be vulnerable.
if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (vuln > 1) s = "s of Java are";
  else s = " of Java is";

  report =
    '\n' +
    'The following vulnerable instance'+s+' installed on the\n' +
    'remote host :\n' +
    info;
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else
{
  installed_versions = substr(installed_versions, 3);
  if (" & " >< installed_versions)
    exit(0, "The Java "+installed_versions+" installations on the remote host are not affected.");
  else
    audit(AUDIT_INST_VER_NOT_VULN, "Java", installed_versions);
}
