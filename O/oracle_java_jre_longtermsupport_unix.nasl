#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(71463);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Oracle Java JRE Premier Support and Extended Support Version Detection (Unix)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains one or more versions of the Oracle Java JRE
that require long-term support.");
  script_set_attribute(attribute:"description", value:
"According to its version, there is at least one install of Oracle
(formerly Sun) Java JRE on the remote host that is potentially under
either Premier Support or Extended Support.

Note that both support programs require vendor contracts.  Premier
Support provides upgrades and security fixes for five years after the
general availability (GA) date.  Extended Support provides upgrades and
security fixes for three years after Premier Support ends.");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/eol-135779.html");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/us/support/lifetime-support-068561.html");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/support/lifetime-support/");
  script_set_attribute(attribute:"solution", value:
"To continue receiving updates and security fixes, contact the vendor
regarding Premier Support or Extended Support contracts.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2022 Tenable Network Security, Inc.");

  script_dependencies("oracle_java_jre_unsupported_unix.nasl");
  script_require_keys("Host/Java/JRE/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

var info = "";

# This plugin should ignore non-Oracle Java installs
var oracle_installs = get_kb_list("installed_sw/Oracle Java/*/version");
if (empty_or_null(oracle_installs))
  audit(AUDIT_NOT_INST, "Oracle Java JRE under Premier Support or Extended Support");

# Check Premier Support versions first
var jre_premier_support_installs = get_kb_list("Java/JRE/premier_support/*");
if (jre_premier_support_installs)
{
  foreach var path_ver (keys(jre_premier_support_installs))
  {
    var pv = path_ver - "Java/JRE/premier_support/";
    var pieces = pregmatch(string:pv, pattern:"^(.*)/([0-9._]+)$");
    if (info != "") info += '\n';
    if (pieces)
      info +=
              '\n  Path          : ' + str_replace(string:pieces[1], find:"\", replace:"/") +
              '\n  Version       : ' + pieces[2] +
              '\n  Support dates : ' + jre_premier_support_installs[path_ver];
  }
}

if (info)
  info = '\n' + 'The following Java JRE installs are in Premier Support status : \n' + info + '\n';

# Check Extended Support versions next
var extended_info = "";
var jre_extended_support_installs = get_kb_list("Java/JRE/extended_support/*");
if (jre_extended_support_installs)
{
  foreach var path_ver (keys(jre_extended_support_installs))
  {
    pv = path_ver - "Java/JRE/extended_support/";
    pieces = pregmatch(string:pv, pattern:"^(.*)/([0-9._]+)$");
    if (extended_info != "") extended_info += '\n';
    if (pieces)
      extended_info +=
              '\n  Path          : ' + str_replace(string:pieces[1], find:"\", replace:"/") +
              '\n  Version       : ' + pieces[2] +
              '\n  Support dates : ' + jre_extended_support_installs[path_ver];
  }
}

if (extended_info)
  info += '\n' +
          '\n' + 'The following Java JRE installs are in Extended Support status : ' +
          '\n' +
          extended_info +
          '\n';

if (info)
{
  var port = 0;

  if (report_verbosity > 0)
    security_note(port:port, extra:info);
  else
    security_note(port);
}
else audit(AUDIT_NOT_INST, "Oracle Java JRE under Premier Support or Extended Support");
