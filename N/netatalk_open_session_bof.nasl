#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(119780);
  script_version("1.4");
  script_cvs_date("Date: 2019/04/05 23:25:06");

  script_cve_id("CVE-2018-1160");
  script_xref(name:"TRA", value:"TRA-2018-48");

  script_name(english:"Netatalk OpenSession Remote Code Execution");
  script_summary(english:"Checks for the OpenSession Reply.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A file sharing service on the remote host is affected by a remote
code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Apple Filing Protocol (AFP) server running on the remote host is
affected by a remote code execution vulnerability due to a buffer
overflow condition when handling an OpenSession request. An
unauthenticated, remote attacker can exploit this issue, via a
specially crafted message, to execute arbitrary code.");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Netatalk 3.1.12 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1160");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(
    attribute:"see_also",
    value:"http://netatalk.sourceforge.net/3.1/ReleaseNotes3.1.12.html"
  );
  # https://medium.com/tenable-techblog/exploiting-an-18-year-old-bug-b47afe54172
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d202fae"
  );

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_family(english:"Gain a shell remotely");
  script_dependencies("asip-status.nasl");
  script_require_ports("Services/appleshare", 548);
  exit(0);
}

include("byte_func.inc");
include("afp_func.inc");
include("misc_func.inc");
include("global_settings.inc");
include("audit.inc");
include("dump.inc");

port = get_service(svc:"appleshare", default:548, exit_on_fail:TRUE);

AFPSocket = open_sock_tcp(port);

if (!AFPSocket) audit(AUDIT_SOCK_FAIL, port);

srv_quantum = 0xdeadbeef;

data  = '\x01'; # attnquant in open sess
data += '\x0c'; # attnquant size
data += '\xaa\xbb\xcc\xdd';   # overwrites attn_quantum (on purpose)
data += '\x00\x00\x00\x00';   # overwrites datasize
data += mkdword(srv_quantum); # overwrites server_quantum 

req = DSI_Packet(flags:Request, command:OpenSession, data:data);
res = DSI_SendRecv(req);
close(AFPSocket);

# Vulnerable:
# Overwritten 'server_quantum' is reflected back in the OpenSession reply.
if(strlen(res) > 0x16  && 
  # It's an OpenSession reply.
  getbyte(blob:res, pos:0) == Reply &&
  getbyte(blob:res, pos:1) == OpenSession &&
  # Server quantum is in the reply
  getbyte(blob:res, pos:0x10) == 0 && 
  #
  # Overwritten 'server_quantum' is seen.
  #
  # Little endian target
  (getdword(blob:res,pos:0x12, order:BYTE_ORDER_LITTLE_ENDIAN) == srv_quantum
  # Big endian target
  || getdword(blob:res,pos:0x12) == srv_quantum))
{
  resp = hexdump(ddata:res);
  if(strlen(res) > 0x20)
  {
    resp = hexdump(ddata:substr(res, 0, 0x1f)) + "(truncated...)";
  }
  extra =
    "Nessus was able to detect the vulnerability with the following " +
    '\n' + "OpenSession request : " +
    '\n\n' + hexdump(ddata:req)  +
    '\n' + "The request attempts to overwrite the 'server_quantum' " +
    '\n' + "field with the value of " +
    "0x" + toupper(hexstr(mkdword(srv_quantum))) + ", which is returned " +
    '\n' + "in the following OpenSession reply : " +
    '\n\n' + resp;

  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    extra      : extra
  );
}
else
{
  audit(AUDIT_HOST_NOT, "affected");
}
