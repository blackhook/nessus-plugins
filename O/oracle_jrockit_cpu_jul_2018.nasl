#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111214);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id(
    "CVE-2018-2938",
    "CVE-2018-2940",
    "CVE-2018-2941",
    "CVE-2018-2942",
    "CVE-2018-2952",
    "CVE-2018-2964",
    "CVE-2018-2972",
    "CVE-2018-2973"
  );
  script_bugtraq_id(
    104765,
    104768,
    104773,
    104774,
    104775,
    104780,
    104781,
    104782
  );

  script_name(english:"Oracle JRockit R28.3.18 Multiple Vulnerabilities (July 2018 CPU)");
  script_summary(english:"Checks the version of jvm.dll.");

  script_set_attribute(attribute:"synopsis", value:
"A programming platform installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JRockit installed on the remote Windows host is
R28.3.18. It is, therefore, affected by multiple vulnerabilities.
See advisory for details.");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50f36723");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JRockit version R28.3.19 or later as referenced in
the July 2018 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2938");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jrockit");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_jrockit_installed.nasl");
  script_require_keys("installed_sw/Oracle JRockit");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app     = "Oracle JRockit";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
ver     = install['version'];
type    = install['type'];
path    = install['path'];

if (tolower(type) != "jdk") audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);

if (ver =~ "^28(\.3)?$") audit(AUDIT_VER_NOT_GRANULAR, app, ver);
if (ver !~ "^28\.3($|[^0-9])") audit(AUDIT_NOT_INST, app + " 28.3.x");

# Affected :
# 28.3.18
if (ver =~ "^28\.3\.18($|[^0-9])")
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  # The DLL we're looking at is a level deeper in the JDK, since it
  # keeps a subset of the JRE in a subdirectory.
  if (tolower(type) == "jdk")  path += "\jre";
  path += "\bin\jrockit\jvm.dll";

  report =
    '\n  Type              : ' + type +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver  +
    '\n  Fixed version     : 28.3.19' +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);
