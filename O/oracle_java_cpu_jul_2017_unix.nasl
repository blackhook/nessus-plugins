#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101844);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2017-10053",
    "CVE-2017-10067",
    "CVE-2017-10074",
    "CVE-2017-10078",
    "CVE-2017-10081",
    "CVE-2017-10086",
    "CVE-2017-10087",
    "CVE-2017-10089",
    "CVE-2017-10090",
    "CVE-2017-10096",
    "CVE-2017-10101",
    "CVE-2017-10102",
    "CVE-2017-10104",
    "CVE-2017-10105",
    "CVE-2017-10107",
    "CVE-2017-10108",
    "CVE-2017-10109",
    "CVE-2017-10110",
    "CVE-2017-10111",
    "CVE-2017-10114",
    "CVE-2017-10115",
    "CVE-2017-10116",
    "CVE-2017-10117",
    "CVE-2017-10118",
    "CVE-2017-10121",
    "CVE-2017-10125",
    "CVE-2017-10135",
    "CVE-2017-10145",
    "CVE-2017-10176",
    "CVE-2017-10193",
    "CVE-2017-10198",
    "CVE-2017-10243"
  );
  script_bugtraq_id(
    99643,
    99659,
    99662,
    99670,
    99674,
    99703,
    99706,
    99707,
    99712,
    99719,
    99726,
    99731,
    99734,
    99752,
    99756,
    99774,
    99782,
    99788,
    99797,
    99804,
    99809,
    99818,
    99827,
    99832,
    99835,
    99839,
    99842,
    99846,
    99847,
    99851,
    99853,
    99854
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (July 2017 CPU) (Unix)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a programming platform that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 8 Update 141, 7 Update 151,
or 6 Update 161. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists in the 2D component that
    allows an unauthenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-10053)

  - Multiple unspecified flaws exist in the Security
    component that allow an unauthenticated, remote attacker
    to execute arbitrary code. (CVE-2017-10067,
    CVE-2017-10116)

  - An unspecified flaw exists in the Hotspot component that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2017-10074)

  - An unspecified flaw exists in the Scripting component
    that allows an authenticated, remote attacker to impact
    confidentiality and integrity. (CVE-2017-10078)

  - An unspecified flaw exists in the Hotspot component that
    allows an unauthenticated, remote attacker to impact
    integrity. (CVE-2017-10081)

  - Multiple unspecified flaws exist in the JavaFX component
    that allow an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2017-10086, CVE-2017-10114)

  - Multiple unspecified flaws exist in the Libraries
    component that allow an unauthenticated, remote attacker
    to execute arbitrary code. (CVE-2017-10087,
    CVE-2017-10090, CVE-2017-10111)

  - An unspecified flaw exists in the ImageIO component that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2017-10089)

  - Multiple unspecified flaws exist in the JAXP component
    that allow an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2017-10096, CVE-2017-10101)

  - Multiple unspecified flaws exist in the RMI component
    that allow an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2017-10102, CVE-2017-10107)

  - Multiple unspecified flaws exist in the Server component
    of the Java Advanced Management Console that allow an
    authenticated, remote attacker to impact
    confidentiality, integrity, and availability.
    (CVE-2017-10104, CVE-2017-10145)

  - An unspecified flaw exists in the Deployment component
    that allows an unauthenticated, remote attacker to
    impact integrity. (CVE-2017-10105)

  - Multiple unspecified flaws exist in the Serialization
    component that allow an unauthenticated, remote attacker
    to exhaust available memory, resulting in a denial of
    service condition. (CVE-2017-10108, CVE-2017-10109)

  - An unspecified flaw exists in the AWT component that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2017-10110)

  - Multiple unspecified flaws exist in the JCE component
    that allow an unauthenticated, remote attacker to
    disclose sensitive information. (CVE-2017-10115,
    CVE-2017-10118, CVE-2017-10135)

  - An unspecified flaw exists in the Server component of
    the Java Advanced Management Console that allows an
    unauthenticated, remote attacker to disclose sensitive
    information. (CVE-2017-10117)

  - An unspecified flaw exists in the Server component of
    the Java Advanced Management Console that allows an
    unauthenticated, remote attacker to impact
    confidentiality and integrity. (CVE-2017-10121)

  - An unspecified flaw exists in the Deployment component
    that allows a local attacker to impact confidentiality,
    integrity, and availability. (CVE-2017-10125)

  - Multiple unspecified flaws exist in the Security
    component that allow an unauthenticated, remote attacker
    to disclose sensitive information. (CVE-2017-10176,
    CVE-2017-10193, CVE-2017-10198)

  - An unspecified flaw exists in the JAX-WS component that
    allows an unauthenticated, remote attacker to impact
    confidentiality and availability. (CVE-2017-10243)");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76f5def7");
  # http://www.oracle.com/technetwork/java/javase/8u141-relnotes-3720385.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?755142b1");
  # https://www.oracle.com/technetwork/java/javaseproducts/documentation/javase7supportreleasenotes-1601161.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fbcacca");
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 8 Update 141 / 7 Update 151 / 6 Update
161 or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 95 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10111");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/20");

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

  # Fixes : (JDK|JRE) 8 Update 141 / 7 Update 151 / 6 Update 161
  if (
    ver =~ '^1\\.6\\.0_([0-9]|[0-9][0-9]|1[0-5][0-9]|160)([^0-9]|$)' ||
    ver =~ '^1\\.7\\.0_([0-9]|[0-9][0-9]|1[0-4][0-9]|150)([^0-9]|$)' ||
    ver =~ '^1\\.8\\.0_([0-9]|[0-9][0-9]|1[0-3][0-9]|140)([^0-9]|$)'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_161 / 1.7.0_151 / 1.8.0_141\n';
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
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
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
