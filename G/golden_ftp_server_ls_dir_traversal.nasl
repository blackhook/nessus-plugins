#TRUSTED a0d9cd9a5f335d29a84af2ec44baeeb32754d6c5fedd215fd64e496432559ef6bac113f0a61f013590448d08dde8fca668820a3fa287c6768a5838611932b9e3919f95245321190cac91fae7ff8a7cab35163dbf3e03e178164dfdd96b03c8568d93f6080739952fba327c58952129fdea9945040cdccb111cac485765f7f06d1541f5ece86ef85d294572b6afc4fd3372fe2fcdcc1cd45e2d46a418c69a659654d5c21da7aab38408a2be13b5daa16a68f69e60bad27d87e0fbb3396eacfdfde9d11de71e8f5a46e56b0a3c09005a494fa9911f1d4c75155833e811a468dc24408d7a085e07f27824c65beffe61446325e4b898b5871c6ceea844c574f8dce4bcf93231dde7911abb7c864ec53ecbc1ff0a6198cf09e292c872f2ccdf59394b903488bfff4d9512289e96f603c7dfbc7bcb50a381d645e021cb6d30c6c6d19b37ba72c9d9c29edc672bd65eb5fcec5cd5bb865223022f7635189e91132bca54e11708c5d4a9e0fd952e9d08d2cd1e94648a69b42448374461c68b293674036d309e7d0209927815f1c1402b8d69a5966f39b960a2b87195a3b17ff35273fcf535ede4c1ebe95e95dec079bbf5cd83e1aa25127adb64f61dee106ab806ab57679188e13534d810222de425aaf42acfca85fc7f442bc84174b47688c48b6a3166d7bcfd5ef0d9c0597a3ab4b203db3dd136b267ee043086e95231e750efb64d8d
###
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18615);
  script_version("1.28");

  script_cve_id("CVE-2005-2142");
  script_bugtraq_id(14124);

  script_name(english:"Golden FTP Server <= 2.60 LS Command Traversal Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by information disclosure flaws." );
 script_set_attribute(attribute:"description", value:
"The version of Golden FTP Server installed on the remote host is prone
to multiple information disclosure vulnerabilities.  Specifically, an
authenticated attacker can list the contents of the application
directory, which provides a list of valid users, and learn the
absolute path of any shared directories." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Golden FTP Server 2.70 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-2142");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/01");
 script_cvs_date("Date: 2019/02/26  4:50:08");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:kmint21_software:golden_ftp_server");
 script_end_attributes();

 
  script_summary(english:"Checks for information disclosure vulnerabilities in Golden FTP Server <= 2.60");
  script_category(ACT_ATTACK);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2005-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_overflow.nasl");
  script_require_keys("ftp/login", "ftp/password");
  script_exclude_keys("ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");
include("global_settings.inc");


# nb: to exploit the vulnerability we need to log in.
user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");
if (!user || !pass) {
  exit(0, "ftp/login and/or ftp/password are empty");
}


port = get_ftp_port(default: 21);

soc = ftp_open_and_authenticate( user:user, pass:pass, port:port );
if (!soc)
{
  exit(1, "Cannot login on port "+port+" with supplied FTP credentials");
}


# Make sure it's Golden FTP Server.
send(socket:soc, data: 'SYST\r\n');
s = recv_line(socket:soc, length:4096);
if ("215 WIN32" >!< s) exit(0);


port2 = ftp_pasv(socket:soc);
if (!port2) exit(1, 'Cannot get PASV port from control port ', port, '.');
soc2 = open_sock_tcp(port2, transport:ENCAPS_IP);
if (!soc2) exit(1, 'Connection failed to passive port '+port+'.');

# Identify shared directories on the remote.
send(socket:soc, data: 'LIST/\r\n');
s = recv_line(socket:soc, length:4096);
if (s =~ "^1[0-9][0-9] ") {
  listing = ftp_recv_listing(socket:soc2);
  s = recv_line(socket:soc, length:4096);
}
close(soc2);
ndirs = 0;
foreach line (split(listing, keep:FALSE)) {
  if (line =~ "^d") {
    # nb: dirs may have spaces so we can't just use a simple regex.
    dirs[ndirs] = substr(line, 55);

    # 3 directories should be enough for testing.
    if (++ndirs > 3) break;
  }
}


# Try to exploit the vulnerability.
foreach dir (dirs) {
  # Change into the directory.
  c = 'CWD /' + string(dir) + '\r\n';
  send(socket:soc, data:c);
  s = ftp_recv_line(socket:soc);
  if (egrep(string:s, pattern:"^250[ -]")) {
    port2 = ftp_pasv(socket:soc);
    if (!port2) exit(1, 'Cannot get PASV port from control port ', port, '.');
    soc2 = open_sock_tcp(port2, transport:ENCAPS_IP);
    if (!soc2) exit(1, 'Connection failed to passive port '+port+'.');

    # Look for contents of the application directory.
    send(socket:soc, data: 'LIST \\../\r\n');
    s = ftp_recv_line(socket:soc);
    if (egrep(string:s, pattern:"^1[0-9][0-9][ -]")) {
      listing = ftp_recv_listing(socket:soc2);
      s = recv_line(socket:soc, length:4096);

      # There's a problem if we see the .shr file for our username.
      if ( ' ' + string(user) + '.shr' >< listing) {
        security_warning(port);
        break;
      }
    }
    close(soc2);
  }
}


# Close the connections.
ftp_close(socket:soc);
