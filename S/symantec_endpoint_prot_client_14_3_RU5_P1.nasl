#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(172499);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/13");

  script_cve_id("CVE-2022-37017");
  script_xref(name:"IAVA", value:"2023-A-0001");

  script_name(english:"Symantec Endpoint Protection Client < 14.3 RU5 Security Control Bypass");

  script_set_attribute(attribute:"synopsis", value:
"The version of Symantec Endpoint Protection Client installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection Client (SEP) installed on the remote host is prior to 14.3 RU5 Patch 1.
It is therefore affected by a Security Control Bypass if Client User Interface Password protection and/or Policy
Import/Export Password protection is enabled. (CVE-2022-37017)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/21014
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?017d7aae");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Protection Client version 14.3 RU5 Patch 1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-37017");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/13");

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

include('vcf.inc');

# https://knowledge.broadcom.com/external/article/154575


var app = 'Symantec Endpoint Protection Client';

var display_ver = get_kb_item_or_exit('Antivirus/SAVCE/version');
var edition = get_kb_item('Antivirus/SAVCE/edition');
if(get_kb_item('SMB/svc/ssSpnAv')) audit(AUDIT_INST_VER_NOT_VULN, 'Symantec.cloud Endpoint Protection');

if (isnull(edition)) edition = '';
else if (edition == 'sepsb') app += ' Small Business Edition';

var fixed_ver = '14.3.8282.5000';
var display_fixed_ver = '14.3 RU5 Patch 1 or 14.3 RU6 (14.3.8282.5000 or greater)';

var port, report;

if (ver_compare(ver:display_ver, fix:fixed_ver, strict:FALSE) == -1)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  report =
    '\n  Product           : ' + app +
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : ' + display_fixed_ver +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, display_ver);
