#TRUSTED 1b6e46f0f433648f7e3b906bfb6f8520e68b7166e2366c8995dc01a901486a74c51ec05b21f215bebcb456033353e43b9253aaad257e3b099488af9e126d942ea2f3323cc25df74c83c1bebae30e00ecb90fdbb0de5b0a6021b20d5cdcfd65ef3757e9e0e473b0a1194076817a49dd4c1e10f5d08a1d83c7e5907d00efc02a02c0148012b3673fcc5f867c8128532606084422bbadb5b3efd2cde42f1dbe4862885e3a0afb48023de1faf0971079ff89f023ad5a52cf9470883707c4523626aeae12bfbdf7932cbeecfbcad9dfce8dcda8879f475443684433e802a30c88fc675eaccc3049013271a69877fd403ecaf3d9cf492968b21e8bfb395e6d415546da1eac59ab25cdfbb99792f31d53af2642299c74f3d4600a964397d1569b32c7ebe2d7d3eb27cfedab501ff90e64593fe2fc26d66d267fa50db91033e435aac755f9812208cf1e247f50ac945e17d589aaa7fdcae5d9f66a3b3284da37a2f7dfd785bae1d1c112cfe3342d6e499bca12316023f1506e9550ca5441726b54eef5b763a3aeb31c6324ae5ae7cbc7b6f2c9a0ddb78709b6e9a215d25e173a70b073af5e610091f162f30b8d7456b7354041a244e0fb162b37861c234d3edf638a5c37a8618792b9f3d777b073e6c9753471b8765276e2fdb81b1918a6ba903b8d4ca969fa5585ce60eba41922040b01954ee713dd8090133a1723a23942ae1ee2eb6c
###
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10471);
 script_bugtraq_id(1452);
 script_version ("1.36");
 script_cve_id("CVE-2000-0640");
 script_name(english:"GuildFTPd Traversal Arbitrary File Enumeration");
 script_summary(english:"GuildFTPd check");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server can be used to determine if a given
file exists on the remote host or not, by adding dot-dot-slashes
in front of them. This is caused by the server responding with
different error messages depending on if the file exists or not.

An attacker may use this flaw to gain more knowledge about
this host, such as its file layout. This flaw is specially
useful when used with other vulnerabilities." );
 script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/guildftpd-dir-adv.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to GuildFTPd 0.999.6 or later, as this reportedly fixes the
issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2000-0640");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/07/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/07/08");
 script_cvs_date("Date: 2018/11/05 14:12:07");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"FTP");
 script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("ftp_func.inc");

port = get_ftp_port(default: 21);

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

if(login)
{
  soc = ftp_open_and_authenticate( user:login, pass:pass, port:port );
  if(soc)
  {
    pasv_port = ftp_pasv(socket:soc);
    soc2 = open_sock_tcp(pasv_port, transport:get_port_transport(port));
    req = 'RETR ../../../../../../nonexistent_at_all.txt\r\n';

    send(socket:soc, data:req);
    r = ftp_recv_line(socket:soc);

    if("550 Access denied" >< r)
    {
      close(soc2);
      pasv_port = ftp_pasv(socket:soc);
      soc2 = open_sock_tcp(pasv_port, transport:get_port_transport(port));
      req = 'RETR ../../../../../../../../autoexec.bat\r\n';
      send(socket:soc, data:req);
      r =  recv_line(socket:soc, length:4096);
      r2 = recv_line(socket:soc, length:4096);
      r = string(r) + string(r2);
      close(soc2);
      if("425 Download failed" >< r)
      {
        ftp_close(socket: soc);
        security_hole(port);
        exit(0);
      }
    }
    ftp_close(socket: soc);
    audit(AUDIT_LISTEN_NOT_VULN,"GuildFTPd",port);
  }
}

#
# We could not log in. Then we'll just attempt to 
# grab the banner and check for version <= 0.97
#
r = get_ftp_banner(port: port);
if("GuildFTPD" >< r)
{
  r = strstr(r, "Version ");
  if(egrep(string:r, pattern:".*Version 0\.([0-8].*|9[0-7]).*"))
  {
    security_hole(port);
    exit(0);
  }
  audit(AUDIT_LISTEN_NOT_VULN,"GuildFTPd",port);
}
audit(AUDIT_NOT_DETECT,"GuildFTPd",port);
