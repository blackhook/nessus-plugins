#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132960);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/21");

  script_cve_id(
    "CVE-2019-13117",
    "CVE-2019-13118",
    "CVE-2019-16168",
    "CVE-2020-2583",
    "CVE-2020-2585",
    "CVE-2020-2590",
    "CVE-2020-2593",
    "CVE-2020-2601",
    "CVE-2020-2604",
    "CVE-2020-2654",
    "CVE-2020-2655",
    "CVE-2020-2659"
  );
  script_bugtraq_id(109323);
  script_xref(name:"IAVA", value:"2020-A-0023-S");

  script_name(english:"Oracle Java SE 1.7.0_251 / 1.8.0_241 / 1.11.0_6 / 1.13.0_2 Multiple Vulnerabilities (Jan 2020 CPU) (Unix)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a programming platform that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 7 Update 251, 8 Update 241,
11 Update 6, or 13 Update 2. It is, therefore, affected by multiple
vulnerabilities:

  - Oracle Java SE and Java SE Embedded are prone to a severe division by zero, over 'Multiple' protocol.
    This issue affects the 'SQLite' component.(CVE-2019-16168)

  - Oracle Java SE and Java SE Embedded are prone to format string vulnerability, leading to a read
    uninitialized stack data over 'Multiple' protocol. This issue affects the 'libxst' component.
    (CVE-2019-13117, CVE-2019-13118)

  - Oracle Java SE and Java SE Embedded are prone to a remote security vulnerability. An unauthenticated
    remote attacker can exploit this over 'Kerberos' protocol. This issue affects the 'Security' component.
    (CVE-2020-2601, CVE-2020-2590)

  - Oracle Java SE/Java SE Embedded are prone to a remote security vulnerability. An unauthenticated
    remote attacker can exploit this overmultiple protocols. This issue affects the 'Serialization' component.
    (CVE-2020-2604, CVE-2020-2583)

  - Oracle Java SE/Java SE Embedded are prone to a remote security vulnerability. Tn unauthenticated
    remote attacker can exploit this over multiple protocols. This issue affects the 'Networking' component.
    (CVE-2020-2593, CVE-2020-2659)

  - Oracle Java SE are prone to a remote security vulnerability. An unauthenticated remote attacker can exploit
    this over multiple protocols. This issue affects the 'Libraries' component. (CVE-2020-2654)

  - Oracle Java SE are prone to a multiple security vulnerability. An unauthenticated remote attacker can exploit
    this over multiple protocols. This issue affects the 'JavaFX' component. (CVE-2020-2585)

  - Oracle Java SE are prone to a multiple security vulnerability. An unauthenticate remote attacker can exploit
    this over 'HTTPS' protocols. This issue affects the 'JSSE' component. (CVE-2020-2655)

Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/security-alerts/cpujan2020.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d22a1e87");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 13 Update 2 , 11 Update 6, 8 Update 241
/ 7 Update 251 or later. If necessary, remove any affected versions.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2604");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed_unix.nasl");
  script_require_keys("Host/Java/JRE/Installed");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

# Check each installed JRE.
installs = get_kb_list_or_exit('Host/Java/JRE/Unmanaged/*');

info = '';
vuln = 0;
vuln2 = 0;
installed_versions = '';
granular = '';

foreach install (list_uniq(keys(installs)))
{
  ver = install - 'Host/Java/JRE/Unmanaged/';
  if (ver !~ "^[0-9.]+") continue;

  installed_versions = installed_versions + ' & ' + ver;

# Fixes : (JDK|JRE) 13 Update 2 / 11 Update 6 / 8 Update 241 / 7 Update 251
  if (
    ver_compare(minver:'1.7.0', ver:ver, fix:'1.7.0_251', regexes:{0:"_(\d+)"}, strict:FALSE) < 0 ||
    ver_compare(minver:'1.8.0', ver:ver, fix:'1.8.0_241', regexes:{0:"_(\d+)"}, strict:FALSE) < 0 ||
    ver_compare(minver:'1.11.0', ver:ver, fix:'1.11.0_6', regexes:{0:"_(\d+)"}, strict:FALSE) < 0 ||
    ver_compare(minver:'1.13.0', ver:ver, fix:'1.13.0_2', regexes:{0:"_(\d+)"}, strict:FALSE) < 0
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.7.0_251 / 1.8.0_241 / 1.11.0_6 / 1.13.0_2\n';
  }
  else if (ver =~ "^[\d\.]+$")
  {
    dirs = make_list(get_kb_list(install));
    foreach dir (dirs)
      granular += 'The Oracle Java version '+ver+' at '+dir+' is not granular enough to make a determination.'+'\n';
  }
  else
  {
    dirs = make_list(get_kb_list(install));
    vuln2 += max_index(dirs);
  }

}

# Report if any were found to be vulnerable.
if (info)
{
  if (vuln > 1) s = 's of Java are';
  else s = ' of Java is';

  report =
    '\n' +
    'The following vulnerable instance'+s+' installed on the\n' +
    'remote host :\n' +
    info;
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
  if (granular) exit(0, granular);
}
else
{
  if (granular) exit(0, granular);

  installed_versions = substr(installed_versions, 3);
  if (vuln2 > 1)
    exit(0, 'The Java '+installed_versions+' installations on the remote host are not affected.');
  else
    audit(AUDIT_INST_VER_NOT_VULN, 'Java', installed_versions);
}
