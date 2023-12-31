#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25709);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2007-3716");
  script_bugtraq_id(24850);

  script_name(english:"Sun Java JRE XML Signature Command Injection (102993)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that may allow arbitrary
command injection.");
  script_set_attribute(attribute:"description", value:
"The version of Sun Java Runtime Environment (JRE) installed on the
remote host reportedly does not securely process XSLT stylesheets
containing XSLT Transforms in XML Signatures.  If an attacker can pass
a specially crafted XSLT stylesheet to a trusted Java application
running on the remote host, arbitrary code could be executed, subject
to the privileges under which the application operates.");
  script_set_attribute(attribute:"see_also", value:"https://www.nccgroup.trust/advisories/2007-04-dsig.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.nccgroup.trust/files/XMLDSIG_Command_Injection.pdf");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/473552/30/0/threaded");
  # http://web.archive.org/web/20080518085541/http://sunsolve.sun.com/search/document.do?assetkey=1-26-102993-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c74c71d0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sun Java JDK and JRE 6 Update 2 or later and remove any
affected versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2022 Tenable Network Security, Inc.");

  script_dependencies("sun_java_jre_installed.nasl");
  script_require_keys("SMB/Java/JRE/Installed");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


# Check each installed JRE.
installs = get_kb_list("SMB/Java/JRE/*");
if (isnull(installs)) exit(1, "The 'SMB/Java/JRE/' KB item is missing.");

info = "";
vuln = 0;
installed_versions = "";

foreach install (list_uniq(keys(installs)))
{
  ver = install - "SMB/Java/JRE/";
  if (ver =~ "^[0-9.]+")
    installed_versions = installed_versions + " & " + ver;
  if (ver =~ "^1\.6\.0_0[01][^0-9]?")
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_02\n';
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
    exit(0, "The Java "+installed_versions+" install on the remote host is not affected.");
}
