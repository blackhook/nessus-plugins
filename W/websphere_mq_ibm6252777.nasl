#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139238);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/16");

  script_cve_id("CVE-2020-4319");
  script_xref(name:"IAVA", value:"2020-A-0345-S");

  script_name(english:"IBM MQ 8.0.0.x < 8.0.0.15 / 9.1.0.x < 9.1.0.6 LTS / 9.1.x < 9.2 CD Information Disclosure Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A message queuing service installed on the remote host is affected
by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM MQ server installed on the remote host is 8.0.0.x prior to 8.0.0.15 
or 9.1.0.x prior to 9.1.0.6 LTS or 9.2 CD and is therefore affected by an information disclosure vulnerability. An 
authenticated, remote attacker can exploit this issue and cause a memory leak and crash the affected host.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6252777");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM MQ 8.0.0.15, 9.1.0.6 LTS, 9.2 CD or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4319");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

# 8.0.x < 8.0.0.15
if (version =~ "^8\.0\.0\.")
{
  fix = '8.0.0.15';
}
# 9.1.x < 9.1.0.6 LTS
else if (version =~ "^9\.1\.0\.")
{
  fix = '9.1.0.6';
}
# 9.1.1 < 9.2 CD
else if (version =~ "^9\.1($|\.)")
{
  fix = '9.2';
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
  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
