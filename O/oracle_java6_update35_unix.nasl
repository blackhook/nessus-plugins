#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64839);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2012-0547",
    "CVE-2012-1682",
    "CVE-2012-3136",
    "CVE-2012-4681"
  );
  script_bugtraq_id(
    55213,
    55336,
    55337,
    55339
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Oracle Java JDK / JRE 6 < Update 35 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a runtime environment that contains methods
that can aid in further attacks.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java Runtime Environment (JRE) 6.x
installed on the remote host is earlier than Update 35. It is, therefore,
affected by the following vulnerabilities:

  - Multiple improper permission check issues were discovered
    in the Beans component in OpenJDK. An untrusted Java
    application or applet could use these flaws to use
    classes from restricted packages, allowing it to bypass
    Java sandbox restrictions. (CVE-2012-4681, CVE-2012-1682,
    CVE-2012-3136, CVE-2012-0547)

Please note this issue is not directly exploitable, rather it can aid in
attacks against other, directly exploitable vulnerabilities, such as
that found in CVE-2012-4681.");
  # http://www.oracle.com/technetwork/topics/security/alert-cve-2012-4681-1835715.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00370937");
  # https://www.oracle.com/technetwork/java/javase/6u35-relnotes-1835788.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47089fc6");
  script_set_attribute(attribute:"solution", value:
"Update to JDK / JRE 6 Update 35 or later and remove, if necessary, any
affected versions.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4681");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java 7 Applet Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed_unix.nasl");
  script_require_keys("Host/Java/JRE/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Check each installed JRE.
installs = get_kb_list_or_exit("Host/Java/JRE/Unmanaged/*");

info="";
vuln = 0;
vuln2 = 0;
installed_versions = "";
granular = "";
foreach install (list_uniq(keys(installs)))
{
  ver = install - "Host/Java/JRE/Unmanaged/";
  if (ver !~ "^[0-9.]+") continue;

  installed_versions = installed_versions + " & " + ver;

  if (ver =~ '^1\\.6\\.0_([0-9]|[0-2][0-9]|3[0-4])([^0-9]|$)')
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_35\n';
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
    exit(0, "The Java "+installed_versions+" installs on the remote host are not affected.");
  else
    exit(0, "The Java "+installed_versions+" install on the remote host is not affected.");
}
