#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65050);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-0809", "CVE-2013-1493");
  script_bugtraq_id(58238, 58296);
  script_xref(name:"CERT", value:"688246");

  script_name(english:"Oracle Java JDK / JRE 6 < Update 43 Remote Code Execution (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a runtime environment that can allow code
execution.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java Runtime Environment (JRE) 6.x
installed on the remote host is earlier than Update 43.  It, therefore,
potentially can allow remote code execution due to the following
vulnerabilities related to the '2D' sub-component :

  - An integer overflow error exists related to handling
    sample model instances that could result in memory
    corruption leading to arbitrary code execution.
    (CVE-2013-0809)

  - An unspecified error exists that could allow memory to
    be overwritten and could allow the security manager to
    be bypassed, thus leading to application crashes or
    arbitrary code execution. (CVE-2013-1493)

Please note this issue affects client deployments only and is exploited
through untrusted 'Java Web Start' applications and untrusted Java
applets.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-142/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-148/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-149/");
  # https://www.oracle.com/technetwork/topics/security/alert-cve-2013-1493-1915081.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb038a9f");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/6u43-relnotes-1915290.html");
  script_set_attribute(attribute:"see_also", value:"http://www.security-explorations.com/en/SE-2012-01-status.html");
  script_set_attribute(attribute:"solution", value:
"Update to JDK / JRE 6 Update 43 or later and remove, if necessary, any
affected versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1493");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java CMM Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed.nasl");
  script_require_keys("SMB/Java/JRE/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Check each installed JRE.
installs = get_kb_list_or_exit("SMB/Java/JRE/*");

info="";
vuln = 0;
installed_versions = "";

foreach install (list_uniq(keys(installs)))
{
  ver = install - "SMB/Java/JRE/";
  if (ver !~ "^[0-9.]+") continue;

  if (ver =~ "^1(\.6)?$") continue;

  installed_versions = installed_versions + " & " + ver;

  if (ver =~ '^1\\.6\\.0_([0-9]|[0-3][0-9]|4[0-2])([^0-9]|$)')
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_43\n';
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
}
else
{
  installed_versions = substr(installed_versions, 3);
  if (" & " >< installed_versions)
    exit(0, "The Java "+installed_versions+" installs on the remote host are not affected.");
  else
    audit(AUDIT_INST_VER_NOT_VULN, "Java", installed_versions);
}
