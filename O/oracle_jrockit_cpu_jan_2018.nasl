#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106139);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id(
    "CVE-2018-2579",
    "CVE-2018-2588",
    "CVE-2018-2599",
    "CVE-2018-2603",
    "CVE-2018-2618",
    "CVE-2018-2629",
    "CVE-2018-2633",
    "CVE-2018-2637",
    "CVE-2018-2657",
    "CVE-2018-2663",
    "CVE-2018-2675",
    "CVE-2018-2678"
  );
  script_bugtraq_id(
    102557,
    102576,
    102612,
    102615,
    102625,
    102629,
    102633,
    102659,
    102661,
    102662,
    102670,
    102675
  );

  script_name(english:"Oracle JRockit R28.3.16 Multiple Vulnerabilities (January 2018 CPU)");
  script_summary(english:"Checks the version of jvm.dll.");

  script_set_attribute(attribute:"synopsis", value:
"A programming platform installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JRockit installed on the remote Windows host is
R28.3.16. It is, therefore, affected by multiple vulnerabilities. See advisory for details.");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29ce2b01");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JRockit version R28.3.17 or later as referenced in
the January 2018 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2637");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/18");

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

if (ver =~ "^28(\.3)?$") audit(AUDIT_VER_NOT_GRANULAR, app, ver);
if (ver !~ "^28\.3($|[^0-9])") audit(AUDIT_NOT_INST, app + " 28.3.x");

# Affected :
# 28.3.16
if (ver =~ "^28\.3\.16($|[^0-9])")
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
    '\n  Installed version : ' + ver  +
    '\n  Fixed version     : 28.3.17' +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);
