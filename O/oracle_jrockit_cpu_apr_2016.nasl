#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(90604);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id("CVE-2016-0695", "CVE-2016-3425", "CVE-2016-3427");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"Oracle JRockit R28.3.9 Multiple Vulnerabilities (April 2016 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A programming platform installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JRockit installed on the remote Windows host is
28.3.9. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists related to the Security
    subcomponent that allows a remote attacker to access
    potentially sensitive information. No other details are
    available. (CVE-2016-0695)

  - An unspecified flaw exists related to the JAXP
    subcomponent that allows a remote attacker to cause a
    denial of service. No other details are available.
    (CVE-2016-3425)

  - An unspecified flaw exists related to the JMX
    subcomponent that allows a remote attacker to execute
    arbitrary code. No other details are available.
    (CVE-2016-3427)");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ffb7b96f");
  # https://www.oracle.com/technetwork/topics/security/cpuapr2016-2881694.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84e0e8de");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JRockit version R28.3.10 or later as referenced in
the April 2016 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3427");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jrockit");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
# 28.3.9
if (ver =~ "^28\.3\.9($|[^0-9])")
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    # The DLL we're looking at is a level deeper in the JDK, since it
    # keeps a subset of the JRE in a subdirectory.
    if (type == "JDK")  path += "\jre";
    path += "\bin\jrockit\jvm.dll";

    report =
      '\n  Type              : ' + type +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver  +
      '\n  Fixed version     : 28.3.10'  +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);
