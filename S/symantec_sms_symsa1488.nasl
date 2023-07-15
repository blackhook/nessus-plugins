#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133410);
  script_version("1.2");
  script_cvs_date("Date: 2020/02/04");

  script_cve_id("CVE-2019-12759");
  script_bugtraq_id(110788);
  script_xref(name:"IAVA", value:"2019-A-0431");

  script_name(english:"Symantec Mail Security for Exchange Live Update Priviledge Escalation Vulnerability (SYMSA1488)");
  script_summary(english:"Checks the version of LuAllRes.dll.");

  script_set_attribute(attribute:"synopsis", value:
"A security application installed on the remote host is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Mail Security for Exchange (SMSMSE) installed on the remote
Windows host is affected by a privilege escalation vulnerability. 

An unauthenticated, remote attacker can exploit this to compromise the 
Live Update software application and gain elevated access to resources that are normally 
protected from an application or user. (CVE-2019-12759)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://support.symantec.com/us/en/article.SYMSA1488.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16d2bfe5");
  # https://support.symantec.com/us/en/article.TECH256503.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d07aa2d");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12759");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:mail_security");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:mail_security_for_microsoft_exchange");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sms_for_domino.nasl", "sms_for_msexchange.nasl");
  script_require_keys("Symantec_Mail_Security/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include('audit.inc');
include('misc_func.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');

get_kb_item_or_exit('Symantec_Mail_Security/Installed');

types = make_list('Domino', 'Exchange');

# Ensure that the affected software is installed.
backend = NULL;
foreach type (types)
{
  if (get_kb_item('SMB/SMS_' + type + '/Installed'))
  {
    backend = type;
    break;
  }
}
if (empty_or_null(backend) || (backend != 'Exchange' && backend != 'Domino'))
  audit(AUDIT_NOT_INST, 'Symantec Mail Security for Domino or Exchange');

path    = get_kb_item_or_exit('SMB/SMS_' + type + '/Path');
version = get_kb_item_or_exit('SMB/SMS_' + type + '/Version');

app     = 'Symantec Mail Security for ' + backend;
fix     = '7.9.1.51';

lu_fix  = '3.3.203.36';
lu_path = '\\LiveUpdate\\'; 

if (isnull(lu_path)) audit(AUDIT_INST_PATH_NOT_VULN, app, path);

lu_path = hotfix_append_path(path:path, value:lu_path + "LuAllRes.dll");
lu_ver = hotfix_get_fversion(path:lu_path);
hotfix_handle_error(error_code:lu_ver['error'], file:lu_path, exit_on_fail:TRUE);
hotfix_check_fversion_end();

lu_ver = join(lu_ver['value'], sep:'.');

if(version =~ "^([0-6]\.|7\.[0-5])")
{
  if (ver_compare(ver:lu_ver, fix:lu_fix, strict:FALSE) >= 0)
    audit(AUDIT_INST_PATH_NOT_VULN, app + ' live update ', lu_ver, path);
}
else  audit(AUDIT_INST_PATH_NOT_VULN, app + 'version : ' + version, path);


port = get_kb_item('SMB/transport');
if (isnull(port)) port = 445;

report =
  '\n  Product           : ' + app + ' ' + branch +
  '\n  Path              : ' + path +
  '\n  Installed version : ' + lu_ver +
  '\n  Fixed version     : ' + lu_fix +
  '\n';

security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
