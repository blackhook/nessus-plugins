#TRUSTED 479b49abc07a03f9a2588b2afa2926d85447e10d01719e2e191342e78d39041189c88b81508162213a449f6d03923c8f27b61005330548663007fe017db036147eee49594ae8d87e36c34dee5749800d0f9e52757753695dc3b75b2a182203b2e83375fb64e1b4ceb00cb8f099a5c88c2c0c797fa93e5ad6a4fb701329ab6d03aefb2e0dd89ad4eac041037210649a113207fce60b7e8b6ff246cde97e6c893a2e1f4c3a79446c3f000caf0ae721534198bfe3c90003e67c46c9eb201503cf9dbb29b515f70e63048a5a393d6335f8fd4b3cf99710b68639c703eb8fc7b6e196e72dbf8422183b12ea821b91b2437202b8bcf0e670f1dca2671f596b53312957cdda0a28c48d79e40820744ee3c1db299a0ec4b4f799b552969064acd4c19ca3b7ffa70fb81b13233518e837fd62e569b3459ae032e27713394ece41b0dc4d53b3058dff27a18aa5c02aa5b684d7264fd6908094794d27559068a6b6037c70b42f53490a5d90cbc6a68150c2bcc4d587d5e993302016b2b3bbfbb1e4152e089efda5a463bd6b6cd6fb865c06b3d310479a5ecdba0b3f679d31a31089810bb124bc830bca943ef361917666f0f7d6aa179f6f21ccf10764061057d0b1d81ad587e13b939e901e7faf082b9d4ca7af7a731356e9628deea8acb57dd122d52acd05707cb9269f3656e3912b08876a28a83f86806f565b035dc9d6b0f7d89843c724
###
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18194);
  script_version("1.30");

  script_cve_id("CVE-2005-1484");
  script_bugtraq_id(13479);

  script_name(english:"Golden FTP Server Pro GET Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a directory traversal flaw." );
 script_set_attribute(attribute:"description", value:
"The version of Golden FTP Server installed on the remote host is prone
to a directory traversal attack.  Specifically, an attacker can read
files located outside a share with '\\..' sequences subject to the
privileges of the FTP server process." );
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2005/May/32" );
 script_set_attribute(attribute:"solution", value:
"Use an FTP proxy to filter malicious character sequences, place the
FTP root on a separate drive, or restrict access using NTFS." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-1484");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/03");
 script_cvs_date("Date: 2018/11/15 20:50:22");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:kmint21_software:golden_ftp_server");
 script_end_attributes();

 
  script_summary(english:"Checks for directory traversal vulnerability in Golden FTP Server");
  script_category(ACT_ATTACK);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2005-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_overflow.nasl");
  script_require_keys("ftp/login", "ftp/password");
  script_exclude_keys("ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");
include('global_settings.inc');


# nb: to exploit the vulnerability we need to log in.
user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");
if (!user || !pass) {
  exit(0, "ftp/login and/or ftp/password are empty");
}


port = get_ftp_port(default: 21);

soc = ftp_open_and_authenticate( user:user, pass:pass, port:port );
if ( !soc )
{
  exit(1, "Cannot login on port "+port+" with supplied FTP credentials");
}

# Make sure it's Golden FTP Server.
send(socket:soc, data:'SYST\r\n');
s = recv_line(socket:soc, length:4096);
if ("215 WIN32" >!< s)
{
 close(soc); exit(0, "Golden FTP Server is not running on port "+port);
}


port2 = ftp_pasv(socket:soc);
if (!port2) exit(1, "Cannot establish FTP passive connection.");
soc2 = open_sock_tcp(port2, transport: ENCAPS_IP);
if (!soc2) exit(1, "Cannot connect on port "+port2+" (passive connection)");

# Identify some directories on the remote.

send(socket:soc, data: 'LIST /\r\n');
s = recv_line(socket:soc, length:4096);
if (s =~ "^1[0-9][0-9] ") {
  listing = ftp_recv_listing(socket:soc2);
  s = recv_line(socket:soc, length:4096);
}
ndirs = 0;
foreach line (split(listing, keep:FALSE)) {
  if (line =~ "^d") {
    # nb: dirs may have spaces so we can't just use a simple regex.
    dirs[++ndirs] = substr(line, 55);
  }
  # 10 directories should be enough for testing.
  if (ndirs > 10) break;
}


# Try to exploit the vulnerability.
foreach dir (dirs) {
  # Iterate several times while trying to get the file's size.
  #
  # nb: this is a handy way to see if the file can be 
  #     retrieved without going through the hassle of 
  #     actually retrieving it.
  i = 0;
  file = "msdos.sys";
  while (++i < 5) {
    c = 'SIZE /' + string(dir) + '/\\..\\' + string(file) + '\r\n';
    send(socket:soc, data: c);
    s = ftp_recv_line(socket:soc);

    # If we get a 213 followed by a size, there's a problem.
    if (egrep(string:s, pattern:"^213 [0-9]+")) {
      security_warning(port);
      exit(0);
    }
  }
}


# Close the connections.
close(soc2);
ftp_close(socket:soc);
exit(0, "The FTP server on port "+port+" is unaffected");
