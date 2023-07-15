#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73570);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2013-6629",
    "CVE-2013-6954",
    "CVE-2014-0429",
    "CVE-2014-0432",
    "CVE-2014-0446",
    "CVE-2014-0448",
    "CVE-2014-0449",
    "CVE-2014-0451",
    "CVE-2014-0452",
    "CVE-2014-0453",
    "CVE-2014-0454",
    "CVE-2014-0455",
    "CVE-2014-0456",
    "CVE-2014-0457",
    "CVE-2014-0458",
    "CVE-2014-0459",
    "CVE-2014-0460",
    "CVE-2014-0461",
    "CVE-2014-0463",
    "CVE-2014-0464",
    "CVE-2014-1876",
    "CVE-2014-2397",
    "CVE-2014-2398",
    "CVE-2014-2401",
    "CVE-2014-2402",
    "CVE-2014-2403",
    "CVE-2014-2409",
    "CVE-2014-2410",
    "CVE-2014-2412",
    "CVE-2014-2413",
    "CVE-2014-2414",
    "CVE-2014-2420",
    "CVE-2014-2421",
    "CVE-2014-2422",
    "CVE-2014-2423",
    "CVE-2014-2427",
    "CVE-2014-2428"
  );
  script_bugtraq_id(
    63676,
    64493,
    65568,
    66856,
    66866,
    66870,
    66873,
    66877,
    66879,
    66881,
    66883,
    66886,
    66887,
    66891,
    66893,
    66894,
    66897,
    66898,
    66899,
    66902,
    66903,
    66904,
    66905,
    66907,
    66908,
    66909,
    66910,
    66911,
    66912,
    66913,
    66914,
    66915,
    66916,
    66917,
    66918,
    66919,
    66920
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (April 2014 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is earlier than 8 Update 5, 7 Update 55,
6 Update 75, or 5 Update 65.  It is, therefore, potentially affected
by security issues in the following components :

  - 2D
  - AWT
  - Deployment
  - Hotspot
  - JAX-WS
  - JAXB
  - JAXP
  - JNDI
  - JavaFX
  - Javadoc
  - Libraries
  - Scripting
  - Security
  - Sound");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e3ee66a");
  # https://www.oracle.com/technetwork/java/javase/8train-relnotes-latest-2153846.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f65f6f6e");
  # https://www.oracle.com/technetwork/java/javase/7u55-relnotes-2177812.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39cb260f");
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  # https://www.oracle.com/technetwork/java/javase/documentation/overview-137139.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84f3023c");
  script_set_attribute(attribute:"solution", value:
"Update to JDK / JRE 8 Update 5, 7 Update 55, 6 Update 75, or
5 Update 65 or later and, if necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 5 Update 65 or later or 6 Update 75 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2022 Tenable Network Security, Inc.");

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

  # Fixes : (JDK|JRE) 8 Update 5 / 7 Update 55 / 6 Update 75 / 5 Update 65
  if (
    ver =~ '^1\\.5\\.0_([0-9]|[0-5][0-9]|6[0-4])([^0-9]|$)' ||
    ver =~ '^1\\.6\\.0_([0-9]|[0-6][0-9]|7[0-4])([^0-9]|$)' ||
    ver =~ '^1\\.7\\.0_([0-9]|[0-4][0-9]|5[0-4])([^0-9]|$)' ||
    ver =~ '^1\\.8\\.0_[0-4]([^0-9]|$)'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.5.0_65 / 1.6.0_75 / 1.7.0_55 / 1.8.0_5\n';
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
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else
{
  installed_versions = substr(installed_versions, 3);
  if (" & " >< installed_versions)
    exit(0, "The Java "+installed_versions+" installs on the remote host are not affected.");
  else
    audit(AUDIT_INST_VER_NOT_VULN, "Java", installed_versions);
}
