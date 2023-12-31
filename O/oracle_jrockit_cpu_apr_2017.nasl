#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99521);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id(
    "CVE-2017-3511",
    "CVE-2017-3526",
    "CVE-2017-3533",
    "CVE-2017-3544"
  );
  script_bugtraq_id(
    97731,
    97733,
    97740,
    97745
  );

  script_name(english:"Oracle JRockit R28.3.13 Multiple Vulnerabilities (April 2017 CPU)");
  script_summary(english:"Checks the version of jvm.dll.");

  script_set_attribute(attribute:"synopsis", value:
"A programming platform installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JRockit installed on the remote Windows host is
R28.3.13. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists in the JCE subcomponent that
    allows a local attacker to gain elevated privileges.
    (CVE-2017-3511)

  - An unspecified flaw exists in the JAXP subcomponent that
    allows an unauthenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-3526)

  - An unspecified flaw exists in the Networking
    subcomponent that allows an unauthenticated, remote
    attacker to update, insert, or delete arbitrary data via
    FTP. (CVE-2017-3533)

  - An unspecified flaw exists in the Networking
    subcomponent that allows an unauthenticated, remote
    attacker to update, insert, or delete arbitrary data via
    SMTP. (CVE-2017-3544)");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?02dc6498");
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3681811.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb4db3c7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JRockit version R28.3.14 or later as referenced in
the April 2017 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3544");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jrockit");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
# 28.3.13
if (ver =~ "^28\.3\.13($|[^0-9])")
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
    '\n  Fixed version     : 28.3.14' +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);
