#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(33486);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2008-3104",
    "CVE-2008-3107",
    "CVE-2008-3108",
    "CVE-2008-3111",
    "CVE-2008-3112",
    "CVE-2008-3113",
    "CVE-2008-3114"
  );
  script_bugtraq_id(
    30140,
    30141,
    30147,
    30148
  );

  script_name(english:"Sun Java J2SE 1.4.2 < Update 18 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Sun Java Runtime Environment (JRE) J2SE 1.4.2 installed
on the remote host is affected by multiple security issues :

  - A buffer overflow vulnerability in font processing 
    module of the JRE could allow an untrusted 
    applet/application to elevate its privilege to read, 
    write and execute local applications with privileges of 
    the user running an untrusted applet (238666). 

  - A vulnerability in the JRE could allow an untrusted 
    applet/application to elevate its privileges to read, 
    write and execute local applications with privileges of 
    the user running an untrusted applet (238967).

  - A buffer overflow vulnerability in Java Web Start could 
    allow an untrusted applet to elevate its privileges to 
    read, write and execute local applications available to 
    users running an untrusted application (238905).

  - A vulnerability in Java Web Start, could allow an 
    untrusted application to create or delete arbitrary 
    files subject to the privileges of the user running the 
    application (238905).

  - A vulnerability in Java Web Start, may disclose the 
    location of Java Web Start cache (238905).

  - A vulnerability in the JRE may allow an untrusted applet 
    to establish connections to services running on the 
    localhost and potentially exploit vulnerabilities 
    existing in the underlying JRE (238968).

  - It should be noted that J2SE 1.4.2 is in its EOL period, 
    and the transition is set to complete on Oct 30th 2008. 
    Please refer to See also section for more details.");
  script_set_attribute(attribute:"see_also", value:"https://download.oracle.com/sunalerts/1019342.1.html");
  script_set_attribute(attribute:"see_also", value:"https://download.oracle.com/sunalerts/1019367.1.html");
  script_set_attribute(attribute:"see_also", value:"https://download.oracle.com/sunalerts/1019375.1.html");
  script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20100513211142/http://sunsolve.sun.com:80/search/document.do?assetkey=1-66-238968-1");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/eol-135779.html");
  script_set_attribute(attribute:"solution", value:
"Update to Sun Java J2SE 1.4.2_18 or later and remove, if necessary, 
any affected versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"D2ExploitPack");
  script_cwe_id(20, 119, 200, 264);

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2022 Tenable Network Security, Inc.");

  script_dependencies("sun_java_jre_installed.nasl");
  script_require_keys("SMB/Java/JRE/Installed");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


# Check each installed JRE.
installs = get_kb_list("SMB/Java/JRE/*");
if (isnull(installs)) exit(0);

info = "";
vuln = 0;
foreach install (list_uniq(keys(installs)))
{
  ver = install - "SMB/Java/JRE/";
  if (ver =~ "^1\.4\.2_(0[0-9]|1[0-7][^0-9]?)")
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.4.2_18\n';
  }
}


# Report if any were found to be vulnerable.
if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity)
  {
    if (vuln > 1) s = "s of Sun's JRE are";
    else s = " of Sun's JRE is";

    report =
      '\n'+
      'The following vulnerable instance' + s + ' installed on the\n' +
      'remote host :\n' +
      info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
