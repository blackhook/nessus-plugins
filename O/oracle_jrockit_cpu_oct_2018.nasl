#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118572);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id(
    "CVE-2018-3149",
    "CVE-2018-3180",
    "CVE-2018-3183",
    "CVE-2018-3214"
  );
  script_bugtraq_id(
    105608,
    105615,
    105617,
    105622
  );

  script_name(english:"Oracle JRockit JDK R28.3.19 Multiple Vulnerabilities (October 2018 CPU)");
  script_summary(english:"Checks the version of jvm.dll.");

  script_set_attribute(attribute:"synopsis", value:
"A programming platform installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JRockit JDK installed on the remote Windows
host is R28.3.19. It is, therefore, affected by multiple
vulnerabilities. See advisory for details.");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec446771");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JRockit version R28.3.20 or later as referenced in
the October 2018 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3183");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/31");

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
version = install['version'];
type    = install['type'];
path    = install['path'];

if (version =~ "^28(\.3)?$") audit(AUDIT_VER_NOT_GRANULAR, app, version);
if (version !~ "^28\.3($|[^0-9])") audit(AUDIT_NOT_INST, app + " 28.3.x");
if (type != "JDK") audit(AUDIT_INST_PATH_NOT_VULN, app + " " + type + " (not JDK)", version, path);

# Affected :
# 28.3.19
if (version =~ "^28\.3\.19($|[^0-9])")
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  # The DLL we're looking at is a level deeper in the JDK, since it
  # keeps a subset of the JRE in a subdirectory.
  if (type == "JDK")  path += "\jre";
  path += "\bin\jrockit\jvm.dll";

  report =
    '\n  Type              : ' + type +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 28.3.20' +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
