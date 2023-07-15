#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104459);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-6331", "CVE-2017-13680", "CVE-2017-13681");
  script_bugtraq_id(101502, 101503, 101504);

  script_name(english:"Symantec Endpoint Protection Client 12.1.x < 12.1 RU6 MP9 / 14.0.x < 14.0 RU1 Multiple Vulnerabilities (SYM17-011)");
  script_summary(english:"Checks the SEP Client version.");

  script_set_attribute(attribute:"synopsis", value:
"The Symantec Endpoint Protection Client installed on the remote host
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection (SEP) Client installed 
on the remote host is 12.1.x prior to 12.1 RU6 MP9 or 14.0.x prior to
14.0 RU1. It is, therefore, affected by a multiple vulnerabilities 
as referenced in the advisory.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://support.symantec.com/en_US/article.SYMSA1418.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a69cd890");
  # https://support.symantec.com/en_US/article.TECH103088.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bcc5e230");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Protection Client version 12.1 RU6 
MP9 / 14.0 RU1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-13681");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("savce_installed.nasl");
  script_require_keys("Antivirus/SAVCE/version");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = 'Symantec Endpoint Protection Client';

display_ver = get_kb_item_or_exit('Antivirus/SAVCE/version');
edition = get_kb_item('Antivirus/SAVCE/edition');
if(get_kb_item('SMB/svc/ssSpnAv')) audit(AUDIT_INST_VER_NOT_VULN, "Symantec.cloud Endpoint Protection");
  

if (isnull(edition)) edition = '';
else if (edition == 'sepsb') app += ' Small Business Edition';

fixed_ver = NULL;

if (display_ver =~ "^12\.1\.")
  fixed_ver = '12.1.7369.6900';
else if (display_ver =~ "^14\.0\.")
  fixed_ver = '14.0.3752.1000';
else
  audit(AUDIT_INST_VER_NOT_VULN, app, display_ver);

if (ver_compare(ver:display_ver, fix:fixed_ver, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report =
    '\n  Product           : ' + app +
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, display_ver);
