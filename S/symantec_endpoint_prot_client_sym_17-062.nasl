#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136619);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2020-5836", "CVE-2020-5837");
  script_xref(name:"IAVA", value:"2020-A-0210");

  script_name(english:"Symantec Endpoint Protection Client < 14.3 Multiple Vulnerabilities (SYMSA1762)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Symantec Endpoint Protection Client installed on the remote host is affected by multiple 
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection (SEP) Client installed on the remote host is prior to 14.3. It is therefore
affected by the following vulnerabilities:

  - An elevation of privilege vulnerability exists. An authenticated, local attacker can exploit this by
    resetting ACLs on a file as a limited user while the tamper feature is disabled, to gain elevated
    privileges. (CVE-2020-5836)

  - An elevation of privilege vulnerability exists. An authenticated, local attacker can exploit this by
    by writing to log files that are replaced by symbolic links to gain elevated privileges. (CVE-2020-5837)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.broadcom.com/security-advisory/security-advisory-detail.html?notificationId=SYMSA1762
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54057529");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Protection Client version 14.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5837");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

fixed_ver = 14.3.558.0000;

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
