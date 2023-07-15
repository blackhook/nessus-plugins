#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103964);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2016-9841",
    "CVE-2016-10165",
    "CVE-2017-10274",
    "CVE-2017-10281",
    "CVE-2017-10285",
    "CVE-2017-10293",
    "CVE-2017-10295",
    "CVE-2017-10309",
    "CVE-2017-10345",
    "CVE-2017-10346",
    "CVE-2017-10347",
    "CVE-2017-10348",
    "CVE-2017-10349",
    "CVE-2017-10350",
    "CVE-2017-10355",
    "CVE-2017-10356",
    "CVE-2017-10357",
    "CVE-2017-10388"
  );
  script_bugtraq_id(
    101315,
    101319,
    101321,
    101328,
    101333,
    101338,
    101341,
    101348,
    101354,
    101355,
    101369,
    101378,
    101382,
    101384,
    101396,
    101413
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (October 2017 CPU) (Unix)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a programming platform that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 9 Update 1, 8 Update 151,
7 Update 161, or 6 Update 171. It is, therefore, affected by multiple
vulnerabilities related to the following components :

  - 2D (Little CMS 2)
  - Deployment
  - Hotspot
  - JAX-WS
  - JAXP
  - Javadoc
  - Libraries
  - Networking
  - RMI
  - Security
  - Serialization
  - Smart Card IO
  - Util (zlib)");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ffb85cfa");
  # https://www.oracle.com/technetwork/java/javase/9-0-1-relnotes-3883752.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfeae1af");
  # http://www.oracle.com/technetwork/java/javase/8u151-relnotes-3850493.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbe7f5cf");
  # https://www.oracle.com/technetwork/java/javaseproducts/documentation/javase7supportreleasenotes-1601161.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fbcacca");
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 9 Update 1, 8 Update 151 / 7 Update 161 /
6 Update 171 or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 95 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9841");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed_unix.nasl");
  script_require_keys("Host/Java/JRE/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Check each installed JRE.
installs = get_kb_list_or_exit("Host/Java/JRE/Unmanaged/*");

info = "";
vuln = 0;
vuln2 = 0;
installed_versions = "";
granular = "";

foreach install (list_uniq(keys(installs)))
{
  ver = install - "Host/Java/JRE/Unmanaged/";
  if (ver !~ "^[0-9.]+") continue;

  installed_versions = installed_versions + " & " + ver;

  # Fixes : (JDK|JRE) 9 Update 1 / 8 Update 151 / 7 Update 161 / 6 Update 171
  if (
    ver =~ '^1\\.6\\.0_([0-9]|[0-9][0-9]|1[0-6][0-9]|170)([^0-9]|$)' ||
    ver =~ '^1\\.7\\.0_([0-9]|[0-9][0-9]|1[0-5][0-9]|160)([^0-9]|$)' ||
    ver =~ '^1\\.8\\.0_([0-9]|[0-9][0-9]|1[0-4][0-9]|150)([^0-9]|$)' ||
    ver =~ '^1\\.9\\.0_00?([^0-9]|$)'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_151 / 1.7.0_161 / 1.8.0_151 / 1.9.0_1\n';
  }
  else if (ver =~ "^[\d\.]+$")
  {
    dirs = make_list(get_kb_list(install));
    foreach dir (dirs)
      granular += "The Oracle Java version "+ver+" at "+dir+" is not granular enough to make a determination."+'\n';
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
  if (report_verbosity > 0)
  {
    if (vuln > 1) s = "s of Java are";
    else s = " of Java is";

    report =
      '\n' +
      'The following vulnerable instance'+s+' installed on the\n' +
      'remote host :\n' +
      info;
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  if (granular) exit(0, granular);
}
else
{
  if (granular) exit(0, granular);

  installed_versions = substr(installed_versions, 3);
  if (vuln2 > 1)
    exit(0, "The Java "+installed_versions+" installations on the remote host are not affected.");
  else
    audit(AUDIT_INST_VER_NOT_VULN, "Java", installed_versions);
}
