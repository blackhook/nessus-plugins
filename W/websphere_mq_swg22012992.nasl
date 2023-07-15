#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108883);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2017-1747", "CVE-2018-1429");
  script_bugtraq_id(103491, 103590);

  script_name(english:"IBM WebSphere 9.0.0.x < 9.0.0.3 / 9.0.0 < 9.0.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of IBM WebSphere MQ.");

  script_set_attribute(attribute:"synopsis", value:
"A message queuing service installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM WebSphere MQ server
installed on the remote host is 9.0.0.x LTS < 9.0.0.3 LTS, or 9.0.x CD
< 9.0.5 CD.");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22012992");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg24044508");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22014046");
  script_set_attribute(attribute:"solution", value:
"Apply Fix Pack version 9.0.0.3 or upgrade to IBM MQ version 9.0.5 per
the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1429");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "IBM WebSphere MQ";
install  = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version  = install['version'];
path = install['path'];
fix = NULL;
xss = FALSE;

# 9.0.0.x < 9.0.0.3
if (version =~ "^9\.0\.0\.[0-2]")
  fix = "9.0.0.3";
# 9.0.x < 9.0.5
else if (version =~ "^9\.0\.[0-4]$")
{
  fix = "9.0.5";
  # XSS does not apply to 9.0.0
  if (version !~ "^9\.0\.0")
  {
    xss = TRUE;
  }
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

# Check affected version
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE, xss:xss);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
