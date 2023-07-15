#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(132341);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/07");

  script_cve_id("CVE-2019-4560");
  script_bugtraq_id(108068);
  script_xref(name:"IAVA", value:"2019-A-0466-S");

  script_name(english:"IBM MQ < 8.0.0.13 / 9.0.0.8 LTS / 9.1.0.4 LTS / 9.1.4 CD Channels DoS (CVE-2019-4560)");

  script_set_attribute(attribute:"synopsis", value:
"A message queuing service installed on the remote host is affected
by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM MQ server installed
on the remote host is 8.0.x prior to 8.0.0.13, 9.0.x prior to 9.0.0.8,
9.1.0.x LTS prior to 9.1.0.4 LTS, or 9.1.4 CD and is therefore
affected by an unspecified flaw related to channels handling that can
allow denial of service.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/1106037");
  script_set_attribute(attribute:"see_also", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/166357");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM MQ 8.0.0.13, 9.0.0.8 LTS, 9.1.0.4 LTS, or 9.1.4 CD as
per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-4560");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ");

  exit(0);
}

include('install_func.inc');

app_name = 'IBM WebSphere MQ';
install  = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
if (install['Type'] != 'Server') audit(AUDIT_HOST_NOT,'affected');

version  = install['version'];
path = install['path'];
fix = NULL;
flag = FALSE;

# 8.0.x < 8.0.0.13
if (version =~ "^8\.0\.0\.")
{
  fix = '8.0.0.13';
}
# 9.0.x < 9.0.0.8
else if (version =~ "^9\.0\.0\.")
{
  fix = '9.0.0.8';
}
# v9.1.0.0 - 9.1.0.4 (LTS is longer ver)
else if (version =~ "^9\.1\.0\.")
{
  fix = '9.1.0.4';
}
# 9.1.x < 9.1.4 (CD is shorter ver)
else if (version =~ "^9\.1\.[0-3]$")
{
  fix = '9.1.4';
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
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
