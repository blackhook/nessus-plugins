#TRUSTED 1605a9b74a64fa6b775cab9a6fee6c8f131eece386f8b42443acb1ece6244420448193328cc8396965ba4f9d41a297b024889e6405ebd844d61982569e7013c128080b576a811236d84b3cb209ec436d1af6d626c28b1cbc451198b5c86341c593de9af771ef0229a8a08bd3866b40310a81f093e3fdb4e64f7953b157cf60694beaab54f9bee99de1438ee4f45096ff6a73273410ee29eeca7b6e90c5e1ff2b1a8f1bfdd4d014c250de2957c5c9b17e7b441eea87cfb4663030762c99b3aac1f6a9e59a5061fddb4cf899598d863171e8b134570062b0d3eef296ea8d651fe947654ea5a7542412e703ab43744e29adb9b2c660f792201dfdc69cb9eb877ce041a49bc469439853b148b9c4f48663c8e447a2a37eee5ac580a07d9ac13f488bc0ab27c03b8edb4ed72559b7de6c901af64ddd98ac122e0f62b4a5960d61a732d3141a6f84bcbd7049b7482dad9f7244595aa0697ff37083a2f5963a435db723a1f246f35e1650855cca48895a6aa324f086cafd2b698d65eea2eb382f2914f79dc4a12d0f228c7e33187186f8bdbd6159c73fd8b469544de4f1426d4d7acf321085002eee337842983898ce2a01d4867c6c9b4c6923b1e2abea0052b7352e5f4478e37d186d837251966e9f2de22a85fcb2fa9058ffcb7f65cc87691712c26b41ddb39e43aa94a91a63ec405304d9e0296188e2955e43c765faf28354a9de9e
###
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added BugtraqID and CAN
#
# GPL
#
# References:
# Date:  Wed, 12 Sep 2001 04:36:22 -0700 (PDT)
# From: "ByteRage" <byterage@yahoo.com>
# Subject: EFTP Version 2.0.7.337 vulnerabilities
# To: bugtraq@securityfocus.com
#

include("compat.inc");

if(description)
{
  script_id(11093);
  script_version("1.31");
  script_cvs_date("Date: 2018/11/15 20:50:22");

  script_bugtraq_id(3333);

  script_name(english:"EFTP Nonexistent File Request Installation Directory Disclosure");
  script_summary(english:"EFTP installation directory disclosure.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EFTP installed on the remote host reveals its
installation directory if sent a request for a nonexistent file.  An
authenticated attacker may leverage this flaw to gain more knowledge
about the affected host, such as its filesystem layout.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2001/Sep/135" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.2 or higher, as it has been reported to fix this
vulnerability.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"score from a more in depth analysis done by Tenable");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value: "2002/08/18");
  
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2002-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
  script_require_ports("Services/ftp", 21);
  script_require_keys("ftp/login");
  exit(0);
}

include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");

cmd[0] = "GET";
cmd[1] = "MDTM";

port = get_ftp_port(default: 21);

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

if (!login)
{
  if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
  else login = "ftp";
}
if (!pass)
{
  if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
  else pass = "nessus@nessus.org";
}

soc = ftp_open_and_authenticate( user:login, pass:pass, port:port );
if ( isnull(soc) )
  exit(1, "Cannot authenticate on port " + port + ".");

for (i = 0; i < 2; i=i+1)
{
  req = string(cmd[i]) + ' nessus' + string(rand()) + '\r\n';
  send(socket:soc, data:req);
  r = ftp_recv_line(socket:soc);
  if (egrep(string:r, pattern:" '[A-Za-z]:\\'"))
  {
    security_warning(port);
    ftp_close(socket:soc);
    exit(0);
  }
}
ftp_close(socket:soc);
audit(AUDIT_LISTEN_NOT_VULN, 'EFTP', port);
