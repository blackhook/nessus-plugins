#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124567);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/19");

  script_cve_id("CVE-2018-1925");
  script_bugtraq_id(108068);
  script_xref(name:"IAVA", value:"2019-A-0137-S");

  script_name(english:"IBM MQ 9.1.0.x LTS < 9.1.0.2 LTS / 9.1.1 CD Console Weak Cryptography Man in the Middle Vulnerability (CVE-2018-1925)");
  script_summary(english:"Checks the version of IBM MQ.");

  script_set_attribute(attribute:"synopsis", value:
"A message queuing service installed on the remote host is affected
by a man in the middle vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM MQ server installed
on the remote host is 9.1.0.x LTS < 9.1.0.2 LTS, or 9.1.1 CD and is
therefore affected by an unspecified man in the middle vulnerability
in the IBM MQ Console due to weaker than expected cryptographic
algorithms.");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=ibm10744713");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM MQ 9.1.2 CD or IBM MQ 9.1.0.2 LTS as per the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1925");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/03");

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

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "IBM WebSphere MQ";
install  = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

version  = install['version'];
path = install['path'];
fix = NULL;
flag = FALSE;

# v9.1.0.0 - 9.1.0.1
if (version =~ "^9\.1\.0\.[01]$")
{
  fix = "9.1.0.2";
}
else if (version =~ "^9\.1\.1($|\.)")
{
  fix = "9.1.2";
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
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
