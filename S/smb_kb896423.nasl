#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(19407);
 script_version("1.38");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/05");

 script_cve_id("CVE-2005-1984");
 script_bugtraq_id (14514);
 script_xref(name:"MSFT", value:"MS05-043");
 script_xref(name:"MSKB", value:"896423");

 script_name(english:"MS05-043: Vulnerability in Printer Spooler Service Could Allow Remote Code Execution (896423) (uncredentialed check)");
 script_summary(english:"Determines the presence of update 896423 (remote check)");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to a flaw in the
Spooler service.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Print Spooler service that
may allow an attacker to execute code on the remote host or crash the
spooler service.

An attacker can execute code on the remote host with a NULL session
against :

  - Windows 2000

An attacker can crash the remote service with a NULL session against :

  - Windows 2000
  - Windows XP SP1

An attacker needs valid credentials to crash the service against :

  - Windows 2003
  - Windows XP SP2");
 # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2005/ms05-043
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f514685");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-1984");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/07/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/09");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2022 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("smb_nativelanman.nasl");
 script_require_keys("Host/OS/smb");
 script_require_ports(139,445);
 exit(0);
}

#

include ('smb_func.inc');

function ReplyOpenPrinter ()
{
 local_var fid, data, rep, name;

 fid = bind_pipe (pipe:"\spoolss", uuid:"12345678-1234-abcd-ef00-0123456789ab", vers:1);
 if (isnull (fid))
   return 0;

 name = session_get_hostname();

 # only unicode is supported
 if (session_is_unicode ())
   name = class_name(name:name);
 else
 {
   session_set_unicode(unicode:1);
   name = class_name(name:name);
   session_set_unicode(unicode:0);
 }

 data = name +
	raw_dword (d:0) +
	raw_dword (d:0) +
	raw_dword (d:0x201) +
	raw_dword (d:0x534E54) +
        raw_dword (d:0x201) +
        crap (data:"A", length:0x201);


 data = dce_rpc_pipe_request (fid:fid, code:0x3a, data:data);
 if (!data)
   return 0;

 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen(rep) != 24))
   return 0;

 return 1;
}

os = get_kb_item ("Host/OS/smb") ;
if ( ! os || "Windows" >!< os || "Windows 4.0" >< os || "Windows 5.2" >< os ) exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 445;

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

name	= kb_smb_name();

session_init(socket:soc, hostname:name);
r = NetUseAdd(share:"IPC$");
if ( r == 1 )
{
 ret = ReplyOpenPrinter();
 if (ret == 1)
   security_report_v4(port:port, severity:SECURITY_HOLE);

 NetUseDel();
}
