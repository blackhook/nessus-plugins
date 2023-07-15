#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171960);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/01");

  script_cve_id("CVE-2022-25631");
  script_xref(name:"IAVA", value:"2023-A-0001");

  script_name(english:"Symantec Endpoint Protection Client < 14.3.5470.3000 / 14.3 RU4 < 14.3.7419.4000 / 14.3 RU5 < 14.3.8289.5000 / 14.3 RU6 < 14.3.9210.6000 Privilege Elevation (21165)");

  script_set_attribute(attribute:"synopsis", value:
"The Symantec Endpoint Protection Client installed on the remote host is affected by a privilege elevation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection (SEP) Client installed on the remote host is affected by an elevation of
privilege vulnerability, which is a type of issue whereby an attacker may attempt to compromise the software application
to gain elevated privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/21165
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5a89f7c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Protection Client version 14.3 RU1 MP1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-25631");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("savce_installed.nasl");
  script_require_keys("Antivirus/SAVCE/version");
  script_require_ports(139, 445);

  exit(0);
}

var app = 'Symantec Endpoint Protection Client';

var display_ver = get_kb_item_or_exit('Antivirus/SAVCE/version');
var edition = get_kb_item('Antivirus/SAVCE/edition');
if(get_kb_item('SMB/svc/ssSpnAv')) audit(AUDIT_INST_VER_NOT_VULN, 'Symantec.cloud Endpoint Protection');

if (empty_or_null(edition)) edition = '';
else if (edition == 'sepsb') app += ' Small Business Edition';

var port, report, fixed_ver;
var vuln = FALSE;

# https://knowledge.broadcom.com/external/article/154575
if (ver_compare(ver:display_ver, fix:'14.3.5470.3000', minver:'0.0', strict:FALSE) == -1)
{
  vuln = TRUE;
  fixed_ver = '14.3.5470.3000';
}
else if (ver_compare(ver:display_ver, fix:'14.3.7419.4000', minver:'14.3.7388.4000', strict:FALSE) == -1)
{
  vuln = TRUE;
  fixed_ver = '14.3.7419.4000';
}
else if (ver_compare(ver:display_ver, fix:'14.3.8289.5000', minver:'14.3.8259.5000', strict:FALSE) == -1)
{
  vuln = TRUE;
  fixed_ver = '14.3.8289.5000';
}
else if (ver_compare(ver:display_ver, fix:'14.3.9210.6000', minver:'14.3.9205.6000', strict:FALSE) == -1)
{
  vuln = TRUE;
  fixed_ver = '14.3.9210.6000';
}

if (vuln)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  report =
    '\n  Product           : ' + app +
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, display_ver);
