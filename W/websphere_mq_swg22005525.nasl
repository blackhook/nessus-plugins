#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105082);
  script_version("1.5");
  script_cvs_date("Date: 2018/08/07 11:56:12");

  script_cve_id("CVE-2017-1341", "CVE-2017-1433");
  script_bugtraq_id(102042);

  script_name(english:"IBM WebSphere MQ 7.5.x / 8.0.0.x < 8.0.0.8 / 9.0.x < 9.0.4 / 9.0.0.x < 9.0.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of IBM WebSphere MQ.");

  script_set_attribute(attribute:"synopsis", value:
"A message queuing service installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM WebSphere MQ server
installed on the remote Windows host is 7.5.x without patch APAR 
IT15943, 8.0.0.x prior to 8.0.0.8, 9.0.x prior to 9.0.4, or 9.0.0.x 
prior to 9.0.0.2. It is, therefore, affected by multiple 
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22005400");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22005525");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WebSphere MQ version 8.0.0.8 / 9.0.4 / 9.0.0.2 or later.
  - For version 7.5.x, apply the patch APAR IT15943.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

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
path     = install['path'];
fix      = NULL;
flag     = FALSE;

if(version =~ "^7\.5\.0\.[0-8]")
{
  fix = "Apply Interim Fix APAR IT15943";
  flag = TRUE;
}
else if(version =~ "^8\.0\.0\.[0-7]")
  fix = "8.0.0.8";
else if(version =~ "^9\.0\.[123]")
  fix = "9.0.4";
else if(version =~ "^9\.0\.0\.[01]")
  fix = "9.0.0.2";
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

# Check affected version
if(flag || ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
