#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66943);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2013-1500",
    "CVE-2013-1571",
    "CVE-2013-2400",
    "CVE-2013-2407",
    "CVE-2013-2412",
    "CVE-2013-2437",
    "CVE-2013-2442",
    "CVE-2013-2443",
    "CVE-2013-2444",
    "CVE-2013-2445",
    "CVE-2013-2446",
    "CVE-2013-2447",
    "CVE-2013-2448",
    "CVE-2013-2449",
    "CVE-2013-2450",
    "CVE-2013-2451",
    "CVE-2013-2452",
    "CVE-2013-2453",
    "CVE-2013-2454",
    "CVE-2013-2455",
    "CVE-2013-2456",
    "CVE-2013-2457",
    "CVE-2013-2458",
    "CVE-2013-2459",
    "CVE-2013-2460",
    "CVE-2013-2461",
    "CVE-2013-2462",
    "CVE-2013-2463",
    "CVE-2013-2464",
    "CVE-2013-2465",
    "CVE-2013-2466",
    "CVE-2013-2467",
    "CVE-2013-2468",
    "CVE-2013-2469",
    "CVE-2013-2470",
    "CVE-2013-2471",
    "CVE-2013-2472",
    "CVE-2013-2473",
    "CVE-2013-3743",
    "CVE-2013-3744"
  );
  script_bugtraq_id(
    60617,
    60618,
    60619,
    60620,
    60621,
    60622,
    60623,
    60624,
    60625,
    60626,
    60627,
    60629,
    60630,
    60631,
    60632,
    60633,
    60634,
    60635,
    60636,
    60637,
    60638,
    60639,
    60640,
    60641,
    60643,
    60644,
    60645,
    60646,
    60647,
    60649,
    60650,
    60651,
    60652,
    60653,
    60654,
    60655,
    60656,
    60657,
    60658,
    60659
  );
  script_xref(name:"CERT", value:"225657");
  script_xref(name:"EDB-ID", value:"27754");
  script_xref(name:"EDB-ID", value:"27943");
  script_xref(name:"EDB-ID", value:"28050");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/18");

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (June 2013 CPU) (Unix)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a programming platform that is
potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is earlier than or equal to 7 Update 21,
6 Update 45 or 5 Update 45.  It is, therefore, potentially affected by
security issues in the following components :

  - 2D
  - AWT
  - CORBA
  - Deployment
  - Hotspot
  - Install
  - JDBC
  - JMX
  - Libraries
  - Networking
  - Serialization
  - Serviceability
  - Sound");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-132/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-151/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-152/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-153/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-154/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-155/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-156/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-157/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-158/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-159/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-160/");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2013/Aug/211");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2013/Aug/276");
  # http://www.oracle.com/technetwork/topics/security/javacpujun2013-1899847.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a094a6d7");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/eol-135779.html");
  script_set_attribute(attribute:"solution", value:
"Update to JDK / JRE 5 Update 51, 6 Update 51, 7 Update 25 or later
and, if necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 5 Update 51 or later or 6 Update 51 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2473");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java storeImageArray() Invalid Array Indexing Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2022 Tenable Network Security, Inc.");

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

  if (
    ver =~ '^1\\.5\\.0_([0-9]|[0-3][0-9]|4[0-5])([^0-9]|$)' ||
    ver =~ '^1\\.6\\.0_([0-9]|[0-3][0-9]|4[0-5])([^0-9]|$)' ||
    ver =~ '^1\\.7\\.0_([0-9]|[0-1][0-9]|2[0-1])([^0-9]|$)'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.5.0_51 / 1.6.0_51 / 1.7.0_25\n';
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
    exit(0, "The Java "+installed_versions+" installs on the remote host are not affected.");
  else
    exit(0, "The Java "+installed_versions+" install on the remote host is not affected.");
}
