#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118227);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2018-3136",
    "CVE-2018-3139",
    "CVE-2018-3149",
    "CVE-2018-3150",
    "CVE-2018-3157",
    "CVE-2018-3169",
    "CVE-2018-3180",
    "CVE-2018-3183",
    "CVE-2018-3209",
    "CVE-2018-3211",
    "CVE-2018-3214",
    "CVE-2018-13785"
  );
  script_bugtraq_id(
    105587,
    105590,
    105591,
    105595,
    105597,
    105599,
    105601,
    105602,
    105608,
    105615,
    105617,
    105622
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (October 2018 CPU) (Unix)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a programming platform that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 11 Update 1, 8 Update 191,
7 Update 201, or 6 Update 211. It is, therefore, affected by
multiple vulnerabilities :

  - An unspecified vulnerability in the Java SE Embedded
    component of Oracle Java SE in the Deployment (libpng)
    subcomponent could allow an unauthenticated, remote
    attacker with network access via HTTP to compromise
    Java SE. (CVE-2018-13785)
 
  - An unspecified vulnerability in the Java SE Embedded
    component of Oracle Java SE in the Hotspot subcomponent
    that could allow an unauthenticated, remote attacker
    with network access via multiple protocols to compromise
    Java SE (CVE-2018-3169)

  - An unspecified vulnerability in the Java SE component of
    Oracle Java SE in the JavaFX subcomponent could allow an
    unauthenticated, remote attacker with network access via
    multiple protocols to compromise Java SE.
    (CVE-2018-3209)

  - An unspecified vulnerability in the Java SE, Java SE
    Embedded, and JRockit component of Oracle Java SE in
    the JNDI subcomponent could allow an unauthenticated,
    remote attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded, and
    JRockit. (CVE-2018-3149)
    
  - An unspecified vulnerability in the Java SE, Java SE
    Embedded, JRockit component of Oracle Java SE in the
    JSSE subcomponent could allow an unauthenticated,
    remote attacker with network access via SSL/TLS to
    compromise Java SE, Java SE Embedded, or JRockit.
    (CVE-2018-3180)

  - An unspecified vulnerability in the Java SE, Java SE
    Embedded component of Oracle Java SE in the Networking
    subcomponent could allow an unauthenticated, remote
    attacker with network access via multiple protocols to
    compromise Java SE or Java SE Embedded. (CVE-2018-3139)

  - An unspecified vulnerability in the Java SE, Java SE
    Embedded, JRockit component of Oracle Java SE in the
    Scripting subcomponent could allow an unauthenticated,
    remote attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded, or
    JRockit. (CVE-2018-3183)

  - An unspecified vulnerability in the Java SE, Java SE
    Embedded component of Oracle Java SE in the Security
    subcomponent could allow an unauthenticated, remote
    attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. (CVE-2018-3136)

  - An unspecified vulnerability in the Java SE, Java SE
    Embedded component of Oracle Java SE in the
    Serviceability subcomponent could allow a low privileged
    attacker with logon to the infrastructure where Java SE,
    Java SE Embedded executes to compromise Java SE, Java SE
    Embedded. (CVE-2018-3211)

  - An unspecified vulnerability in the Java SE component of
    Oracle Java SE in the Sound subcomponent could allow an
    unauthenticated, remote attacker with network access via
    multiple protocols to compromise Java SE.
    (CVE-2018-3157)

  - An unspecified vulnerability in the Java SE component of
    Oracle Java SE in the Utility subcomponent could allow an
    unauthenticated, remote attacker with network access via
    multiple protocols to compromise Java SE.
    (CVE-2018-3150)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?705136d8");
  # https://www.oracle.com/technetwork/java/javase/11-0-1-relnotes-5032023.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?278f2590");
  # https://www.oracle.com/technetwork/java/javase/8u191-relnotes-5032181.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?adc8ef52");
  # https://www.oracle.com/technetwork/java/javaseproducts/documentation/javase7supportreleasenotes-1601161.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fbcacca");
  # https://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de812f33");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 11 Update 1, 8 Update 191 / 7 Update 201 /
6 Update 211 or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 95 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3183");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

  # Fixes : (JDK|JRE) 11 Update 1 / 8 Update 191 / 7 Update 201 / 6 Update 211
  if (
    ver =~ '^1\\.6\\.0_([0-9]|[0-9][0-9]|1[0-9][0-9]|20[0-9]|210)([^0-9]|$)' ||
    ver =~ '^1\\.7\\.0_([0-9]|[0-9][0-9]|1[0-9][0-9]|200)([^0-9]|$)' ||
    ver =~ '^1\\.8\\.0_([0-9]|[0-9][0-9]|1[0-8][0-9]|190)([^0-9]|$)' ||
    ver =~ '^1\\.11\\.0_(0[0]|0?[0])([^0-9]|$)'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_211 / 1.7.0_201 / 1.8.0_191 / 1.11.0_1\n';
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
