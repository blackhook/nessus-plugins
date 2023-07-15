#TRUSTED 672aa27865bedc9cb84985d8c18435d663d7671e03ac46bc2a6dc8bb71289637637e24245b6aa8331b4bc1579ee92daba1f764b17d5d3140a8292e11b249a2ccd50d831bf3f1aecedad61a6b3b06824e26f0a17336d821d00f3f54774eeec7b92d3cfd874f9070631333823b747f0fe867f24c9ea0adc0dc1118dfd6456a60895a8ac0acdbd16dad54aa7652d69f4b9b7fd9095a973e7cb37f547f7cb470d750505b480aa6d7513e89f5205d5654e2a1bfbfb9f374161efeada2ea26c14f8bddf20e098ed649b49630731615ca16c2433d558478140d928d0538508bfeb5b675f06a3d19bc620f7fb84d6036b40eecdae930d66401b855ca65c686806c7e505716500106d022b8bb202a4d1a5875d183da1825ad4371bb0bc47f9f7e3e0bb1160c9dcabdf78f1559c0bb94d3bcec56f4eb8ce2ef3c0cff1f77de35594f9640c83e5656af643d821bddcd02829b8c7cf89c460898f514d1a6543a89dfbded5c122ee05c55e657e4cbf7a3c6c787e3b6d47d29d7908825efd6e76f7f6c2d74bdf7bcbbc34d6b93935187a005c208134cdec384db37dc04c979155efedd760554e4648a6f2a10b95bc230b7df6046a81d1f5fa2e609ea43d3b70cbe97d6a95ed666f90ee799734f954a2e705f1b0648a264856a6dcbc9c2606f584b1c11ede909a64a0a92c3b72abffc5f35641f2511c128a89da5e91c1ec39086a29510a81a1017
#
# (C) Tenable Network Security, Inc.
#

# References:
#
# From: matrix@infowarfare.dk
# Subject: Directory traversal vulnerabilities found in NITE ftp-server version 1.83
# Date: Wed, 15 Jan 2003 13:10:46 +0100
#
# From: "Peter Winter-Smith" <peter4020@hotmail.com>
# To: vulnwatch@vulnwatch.org, vuln@secunia.com, bugs@securitytracker.com
# Date: Wed, 06 Aug 2003 19:41:13 +0000
# Subject: Directory Traversal Vulnerability in 121 WAM! Server 1.0.4.0
#
# Vulnerable:
# NITE ftp-server version 1.83
# 121 WAM! Server 1.0.4.0

include('compat.inc');

if (description)
{
  script_id(11466);
  script_version("1.34");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/11");

  script_cve_id("CVE-2003-1349");
  script_bugtraq_id(6648);

  script_name(english:"Multiple FTP Server Traversal Arbitrary File/Directory Access");
  script_summary(english:"Attempts to set the current directory to the root of the disk");

  script_set_attribute(attribute:"synopsis", value:"The remote FTP server allows arbitrary file access");
  script_set_attribute(attribute:"description", value:
"The remote FTP server allows anybody to switch to the root directory
and read potentially sensitive files.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/vulnwatch/2003/q1/23");
  script_set_attribute(attribute:"solution", value:
"If this is Thomas Krebs Nite Server, upgrade to version 1.85 or later.
Otherwise contact your vendor for the appropriate patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2003-1349");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2003-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"FTP");

  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
  script_require_keys("ftp/login", "Settings/ParanoidReport");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include('ftp_func.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);


var port = get_ftp_port(default: 21);

var soc = ftp_open_and_authenticate( user:"anonymous", pass:"nessus@nessus.org", port:port );
if (!soc)
{
  exit(0, "The FTP server on port "+port+" rejects anonymous connections.");
}
send(socket: soc, data: 'CWD\r\n');
var r = ftp_recv_line(socket: soc);
send(socket: soc, data: 'PWD\r\n');
r = ftp_recv_line(socket: soc);
var matches = egrep(string:r, pattern:'^[0-9]+ *"([^"]+)"');
if (matches) {
  foreach match (split(matches)) {
    var match = chomp(match);
    var v = pregmatch(string:match, pattern:'^[0-9]+ *"([^"]+)"');
    if (! isnull(v)) {
      var cur1 = v[1];
      break;
    }
  }
}

# Loop on vulnerable patterns
var dirs = make_list("\..\..\..\..\..", "/../");

foreach var d (dirs)
{
send(socket: soc, data: 'CWD ' + d + '\r\n');

r = ftp_recv_line(socket: soc);
send(socket: soc, data: 'PWD\r\n');
r = ftp_recv_line(socket: soc);
var matches = egrep(string:r, pattern:'^[0-9]+ *"([^"]+)"');
if (matches) {
  foreach match (split(matches)) {
    match = chomp(match);
    v = pregmatch(string:match, pattern:'^[0-9]+ *"([^"]+)"');
    if (! isnull(v)) {
      var cur2 = v[1];
      break;
    }
  }
}

if (cur1 && cur2)
{
  if (cur1 != cur2)
    security_report_v4(port:port, severity:SECURITY_WARNING);
  ftp_close(socket: soc);
  exit(0);
}

var p = ftp_pasv(socket:soc);
if(p)
{
  var soc2 = open_sock_tcp(p, transport:get_port_transport(port));
  if(soc2)
  {
     send(socket:soc, data: 'LIST\r\n');
     r = ftp_recv_listing(socket:soc2);
     r = tolower(r);
     ftp_recv_line(socket: soc);
     close(soc2);
     if ("autoexec.bat" >< r || "boot.ini" >< r || "config.sys" >< r)
     {
       security_report_v4(port:port, severity:SECURITY_WARNING);
       break;
     }
   }
}
}
ftp_close(socket: soc);
