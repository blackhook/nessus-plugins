#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106190);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2018-2579",
    "CVE-2018-2581",
    "CVE-2018-2582",
    "CVE-2018-2588",
    "CVE-2018-2599",
    "CVE-2018-2602",
    "CVE-2018-2603",
    "CVE-2018-2618",
    "CVE-2018-2627",
    "CVE-2018-2629",
    "CVE-2018-2633",
    "CVE-2018-2634",
    "CVE-2018-2637",
    "CVE-2018-2638",
    "CVE-2018-2639",
    "CVE-2018-2641",
    "CVE-2018-2657",
    "CVE-2018-2663",
    "CVE-2018-2677",
    "CVE-2018-2678"
  );
  script_bugtraq_id(
    102546,
    102556,
    102557,
    102576,
    102584,
    102592,
    102597,
    102605,
    102612,
    102615,
    102625,
    102629,
    102633,
    102636,
    102642,
    102656,
    102659,
    102661,
    102662,
    102663
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (January 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 9 Update 4, 8 Update 161,
7 Update 171, or 6 Update 181. It is, therefore, affected by
multiple vulnerabilities related to the following components :

  - AWT
  - Deployment
  - Hotspot
  - I18n
  - Installer
  - JCE
  - JGSS
  - JMX
  - JNDI
  - JavaFX
  - LDAP
  - Libraries
  - Serialization");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29ce2b01");
  # https://www.oracle.com/technetwork/java/javase/9-0-4-relnotes-4021191.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?793c3773");
  # https://www.oracle.com/technetwork/java/javase/8u162-relnotes-4021436.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc061f9a");
  # https://www.oracle.com/technetwork/java/javaseproducts/documentation/javase7supportreleasenotes-1601161.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fbcacca");
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 9 Update 4, 8 Update 161 / 7 Update 171 /
6 Update 181 or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 95 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2639");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/19");

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

  # Fixes : (JDK|JRE) 9 Update 4 / 8 Update 161 / 7 Update 171 / 6 Update 181
  if (
    ver =~ '^1\\.6\\.0_([0-9]|[0-9][0-9]|1[0-7][0-9]|180)([^0-9]|$)' ||
    ver =~ '^1\\.7\\.0_([0-9]|[0-9][0-9]|1[0-6][0-9]|170)([^0-9]|$)' ||
    ver =~ '^1\\.8\\.0_([0-9]|[0-9][0-9]|1[0-5][0-9]|160)([^0-9]|$)' ||
    ver =~ '^1\\.9\\.0_(00|0?[0-3])([^0-9]|$)'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_181 / 1.7.0_171 / 1.8.0_161 / 1.9.0_4\n';
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

