#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151470);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/09");

  script_cve_id("CVE-2020-12597");
  script_xref(name:"IAVA", value:"2021-A-0300");

  script_name(english:"Symantec Endpoint Protection Client < 14.3 RU1 MP1 DoS (SYMSA18255)");

  script_set_attribute(attribute:"synopsis", value:
"The Symantec Endpoint Protection Client installed on the remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection (SEP) Client installed on the remote host is prior to 14.3 RU1 MP1. It is,
therefore, affected by a denial of service vulnerability due to an unhandled exception in a common driver.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.broadcom.com/security-advisory/content/security-advisories/Symantec-Security-Update/SYMSA18255
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1838de42");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Protection Client version 14.3 RU1 MP1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12597");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("savce_installed.nasl");
  script_require_keys("Antivirus/SAVCE/version");
  script_require_ports(139, 445);

  exit(0);
}

var app = 'Symantec Endpoint Protection Client';

var display_ver = get_kb_item_or_exit('Antivirus/SAVCE/version');
var edition = get_kb_item('Antivirus/SAVCE/edition');
if(get_kb_item('SMB/svc/ssSpnAv')) audit(AUDIT_INST_VER_NOT_VULN, 'Symantec.cloud Endpoint Protection');

if (isnull(edition)) edition = '';
else if (edition == 'sepsb') app += ' Small Business Edition';

# https://knowledge.broadcom.com/external/article/154575
var fixed_ver = '14.3.3580.1100';

var port, report;

if (ver_compare(ver:display_ver, fix:fixed_ver, strict:FALSE) == -1)
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
