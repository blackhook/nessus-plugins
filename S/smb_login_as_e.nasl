#
# (C) Tenable Network Security, Inc.
#

# 09.16.MS03-039-exp.c.php

include('compat.inc');

if(description)
{
  script_id(11839);
  script_version("1.30");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/14");

  script_cve_id("CVE-2003-0528");
  script_bugtraq_id(8459);
  script_xref(name:"MSFT", value:"MS03-039");
  script_xref(name:"MSKB", value:"824146");

  script_name(english:"MS03-039 Exploitation Backdoor Account Detection");
  script_summary(english:"Logs in as 'e'/'asd#321'");

  script_set_attribute(attribute:'synopsis', value:"The remote host has evidence
  of being compromised by a widely known exploit.");

  script_set_attribute(attribute:'description', value:"It was possible to log
into the remote host with the login 'e' and the password 'asd#321'.
A widely available exploit, using one of the vulnerabilities described
in the Microsoft Bulletin MS03-039 creates such an account. This
probably means that the remote host has been compromised by the use of
this exploit.");

  script_set_attribute(attribute:'solution', value:"Re-install the operating system on this host, as it has been compromised.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2003-0528");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  #https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2003/ms03-039
  script_set_attribute(attribute:'see_also', value:"http://www.nessus.org/u?7d4c61df");
  script_set_attribute(attribute:'see_also', value:"https://seclists.org/fulldisclosure/2003/Sep/834");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 2003-2021 Tenable Network Security, Inc.");

  script_dependencies("smb_login.nasl");
  script_require_ports(139, 445);
  script_require_keys("SMB/ProductName");
  script_exclude_keys("global_settings/supplied_logins_only", "SMB/any_login");

  exit(0);
}

#
include("smb_func.inc");

var productname = get_kb_item_or_exit('SMB/ProductName');
if ("windows" >!< tolower(productname)) audit(AUDIT_OS_NOT, 'Windows');

if (get_kb_item("SMB/any_login")) exit(0, "The remote host authenticates users as 'Guest'.");
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

var login = "e";
var pass  = "asd#321";

var port = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED,port);
var soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

session_init(socket:soc, hostname:kb_smb_name());
var r = NetUseAdd(login:rand_str(length:8), password:"", domain:NULL, share:"IPC$");
NetUseDel();
if (r == 1) audit(AUDIT_SHARE_FAIL, "IPC$");

var soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

session_init(socket:soc, hostname:kb_smb_name());
var r = NetUseAdd(login:login, password:pass, domain:NULL, share:"IPC$");
if (r == 1)
{
  if (report_verbosity > 0)
  {
    var report =
      '\n' +
      'Nessus was able to gain access using the following credentials :\n' +
      '\n' +
      '  User     : ' + login + '\n' +
      '  Password : ' + pass + '\n';
    security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  }
  else security_report_v4(port:port, severity:SECURITY_HOLE);
  NetUseDel();
  exit(0);
}
else
{
  NetUseDel();
  audit(AUDIT_HOST_NOT, 'affected');
}