#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111163);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2018-2938",
    "CVE-2018-2940",
    "CVE-2018-2941",
    "CVE-2018-2942",
    "CVE-2018-2952",
    "CVE-2018-2964",
    "CVE-2018-2972",
    "CVE-2018-2973"
  );
  script_bugtraq_id(
    104765,
    104768,
    104773,
    104774,
    104775,
    104780,
    104781,
    104782
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (July 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 10 Update 2, 8 Update 181,
7 Update 191, or 6 Update 201. It is, therefore, affected by
multiple vulnerabilities related to the following components :

  - Concurrency. A difficult to exploit vulnerability allows
    an unauthenticated attacker with network access via
    multiple protocols to compromise Java SE (CVE-2018-2952)

  - Deployment. A difficult to exploit vulnerability allows
    an unauthenticated attacker with network access via
    multiple protocols to compromise Java SE (CVE-2018-2964)

  - JSSE. A difficult to exploit vulnerability allows
    an unauthenticated attacker with network access via
    multiple protocols to compromise Java SE (CVE-2018-2973)

  - Java DB. A difficult to exploit vulnerability allows an
    unauthenticated attacker with network access via
    multiple protocols to compromise Java SE. (CVE-2018-2938)

  - JavaFX. A difficult to exploit vulnerability allows an
    unauthenticated attacker with network access via
    multiple protocols to compromise Java SE. (CVE-2018-2941)

  - Libraries. An easily exploitable vulnerability allows
    an unauthenticated attacker with network access via
    multiple protocols to compromise Java SE. (CVE-2018-2940)

  - Security. A difficult to exploit vulnerability allows
    an unauthenticated attacker with network access via
    multiple protocols to compromise Java SE (CVE-2018-2972)

  - Windows DLL. A difficult to exploit vulnerability allows
    an unauthenticated attacker with network access via
    multiple protocols to compromise Java SE (CVE-2018-2942)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dbb3b1db");
  # https://www.oracle.com/technetwork/java/javase/10-0-2-relnotes-4477557.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a11ccea");
  # https://www.oracle.com/technetwork/java/javase/8u181-relnotes-4479407.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c975c0b");
  # https://www.oracle.com/technetwork/java/javaseproducts/documentation/javase7supportreleasenotes-1601161.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fbcacca");
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 10 Update 2, 8 Update 181 / 7 Update 191 /
6 Update 201 or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 95 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2938");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed.nasl");
  script_require_keys("SMB/Java/JRE/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

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

  # Fixes : (JDK|JRE) 10 Update 2 / 8 Update 181 / 7 Update 191 / 6 Update 201
  if (
    ver =~ '^1\\.6\\.0_([0-9]|[0-9][0-9]|1[0-9][0-9]|200)([^0-9]|$)' ||
    ver =~ '^1\\.7\\.0_([0-9]|[0-9][0-9]|1[0-8][0-9]|190)([^0-9]|$)' ||
    ver =~ '^1\\.8\\.0_([0-9]|[0-9][0-9]|1[0-7][0-9]|180)([^0-9]|$)' ||
    ver =~ '^1\\.10\\.0_(0[01]|0?[01])([^0-9]|$)'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_201 / 1.7.0_191 / 1.8.0_181 / 1.10.0_2\n';
  }
}

# Report if any were found to be vulnerable.
if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    if (vuln > 1) s = "s of Java are";
    else s = " of Java is";

    report =
      '\n' +
      'The following vulnerable instance'+s+' installed on the\n' +
      'remote host :\n' +
      info;
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else
{
  installed_versions = substr(installed_versions, 3);
  if (" & " >< installed_versions)
    exit(0, "The Java "+installed_versions+" installations on the remote host are not affected.");
  else
    audit(AUDIT_INST_VER_NOT_VULN, "Java", installed_versions);
}
