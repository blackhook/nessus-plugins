#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74222);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/07");

  script_cve_id("CVE-2013-4068");
  script_bugtraq_id(62481);

  script_name(english:"IBM Domino 8.5.x < 8.5.3 Fix Pack 5 Interim Fix 1 iNotes Buffer Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of IBM Domino (formerly IBM Lotus
Domino) on the remote host is 8.5.3 prior to 8.5.3 Fix Pack 5 (FP5)
Interim Fix 1 (IF1), and thus is affected by a buffer overflow error
in the iNotes component that could allow an authenticated user to
execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21649476");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21650146");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Domino 8.5.3 FP5 IF1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:domino");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:inotes");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2022 Tenable Network Security, Inc.");

  script_dependencies("domino_installed.nasl");
  script_require_keys("Domino/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "IBM Domino";
ver = get_kb_item_or_exit("Domino/Version");
port = get_kb_item("Domino/Version_provided_by_port");
if (!port) port = 0;

version = NULL;
fix = NULL;
fix_ver = NULL;
fix_pack = NULL;
hotfix = NULL;

# Ensure sufficient granularity
if (ver !~ "^(\d+\.){1,}\d+.*$") audit(AUDIT_VER_NOT_GRANULAR, app_name, port, ver);

# Only check for 8.5.3 versions
if (ver =~ "^8\.5\.3($|[^0-9])")
{
  fix = "8.5.3 FP 5 IF 1";
  fix_ver = "8.5.3";
  fix_pack = 5;
  hotfix = 89;
}
else audit(AUDIT_NOT_LISTEN, app_name + ' 8.5.3.x', port);

# Breakdown the version into components.
version = eregmatch(string:ver, pattern:"^((?:\d+\.){1,}\d+)(?: FP(\d+))?(?: HF(\d+))?$");
if (isnull(version)) audit(AUDIT_UNKNOWN_APP_VER, app_name);

# Use 0 as a placeholder if no FP or HF. Version number itself was
# checked for in the granularity check.
if (!version[2]) version[2] = 0;
else version[2] = int(version[2]);
if (!version[3]) version[3] = 0;
else version[3] = int(version[3]);

# Compare current to fix and report as needed.
if (
  ver_compare(ver:version[1], fix:fix_ver, strict:FALSE) == -1 ||
  (ver_compare(ver:version[1], fix:fix_ver, strict:FALSE) == 0  && version[2] < fix_pack) ||
  (ver_compare(ver:version[1], fix:fix_ver, strict:FALSE) == 0  && version[2] == fix_pack && version[3] < hotfix)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, ver);
