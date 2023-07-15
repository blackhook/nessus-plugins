#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(145218);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2020-14803");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Java SE 1.7.0_291 / 1.8.0_281 / 1.11.0_10 / 1.15.0_2 Information Disclosure (Windows Jan 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business installed on the remote host is prior to 7 Update
291, 8 Update 281, 11 Update 10, or 15 Update 2. It is, therefore, affected by an information disclosure vulnerability
as referenced in the January 2021 CPU advisory. Specifically, an unauthenticated, remote attacker can gain unauthorized
read access to some data accessible to Java SE and Java SE Embedded. Only Java deployments that load and run untrusted
code and rely on the Java sandbox for security are affected. This vulnerability does not apply to Java deployments,
typically in servers, that load and run only trusted code (e.g., code installed by an administrator). 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2021.html#AppendixJAVA");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2021 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14803");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
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
installs = get_kb_list_or_exit('SMB/Java/JRE/*');

info = '';
vuln = 0;
installed_versions = '';

foreach install (list_uniq(keys(installs)))
{
  ver = install - 'SMB/Java/JRE/';
  if (ver !~ "^[0-9.]+") continue;

  installed_versions = installed_versions + ' & ' + ver;

  # Fixes : (JDK|JRE) 15 Update 2 / 11 Update 10 / 8 Update 281 / 7 Update 291
  if (
    ver_compare(minver:'1.7.0', ver:ver, fix:'1.7.0_291', regexes:{0:"_(\d+)"}, strict:FALSE) < 0 ||
    ver_compare(minver:'1.8.0', ver:ver, fix:'1.8.0_281', regexes:{0:"_(\d+)"}, strict:FALSE) < 0 ||
    ver_compare(minver:'1.11.0', ver:ver, fix:'1.11.0_10', regexes:{0:"_(\d+)"}, strict:FALSE) < 0 ||
    ver_compare(minver:'1.15.0', ver:ver, fix:'1.15.0_2', regexes:{0:"_(\d+)"}, strict:FALSE) < 0
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.7.0_291 / 1.8.0_281 / 1.11.0_10 / 1.15.0_2\n';
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

