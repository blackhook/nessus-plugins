#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(108486);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/05");

  script_cve_id("CVE-2018-1388");

  script_name(english:"IBM WebSphere MQ 7.0.1.x ROBOT Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A message queuing service installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM WebSphere MQ server
installed on the remote Windows host is 7.0.1.x without patch APAR 
IJ03658");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/303623");
  script_set_attribute(attribute:"solution", value:
"For version 7.0.1.x, apply the patch APAR IJ03658.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1388");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('install_func.inc');

app_name = 'IBM WebSphere MQ';
install  = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version  = install['version'];
path     = install['path'];
fix      = NULL;
flag     = FALSE;

if(version =~ "^7\.0\.1\.")
{
  fix = 'Apply Interim Fix APAR IJ03658';
  flag = TRUE;
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

# Check affected version
if(flag || ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
