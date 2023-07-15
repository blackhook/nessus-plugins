#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101547);
  script_version("1.4");
  script_cvs_date("Date: 2018/07/12 15:01:51");

  script_cve_id("CVE-2016-8731");
  script_bugtraq_id(99193);

  script_name(english:"Foscam C1 IP Camera FTP Hard Coded Password");
  script_summary(english:"Attempts to log in with r:r credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an FTP server that is using a hard-coded
password.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to log in to the remote FTP server, using the
username 'r' with the password 'r', and identify the remote server as
a vulnerable Foscam C1 IP Camera. A remote attacker can exploit this
to access its FTP service and the mounted Micro-SD card.");
  script_set_attribute(attribute:"see_also", value:"https://www.talosintelligence.com/reports/TALOS-2016-0245/");
  script_set_attribute(attribute:"see_also", value:"http://blog.talosintelligence.com/2017/06/foscam-vuln-details.html");
  script_set_attribute(attribute:"solution", value:
"Update to firmware version V-2.x.2.43 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:foscam:c1_webcam_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:foscam:c1_webcam");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_keys("ftp/login");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ftp", 50021);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

port = get_ftp_port(default:50021);
encaps = get_port_transport(port);

banner = chomp(get_ftp_banner(port:port));
if (!banner) audit(AUDIT_NO_BANNER, port);
if ('Pure-FTPd' >!< banner) audit(AUDIT_NOT_DETECT, "Pure-FTPd", port);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

login = 'r';
password = 'r';
is_auth = ftp_authenticate(socket:soc, user:login, pass:password);

if (!is_auth)
{
  close(soc);
  audit(AUDIT_LISTEN_NOT_VULN, "Pure-FTPd", port);
}

port2 = ftp_pasv(socket:soc);
if (!port2) exit(1, "PASV command failed on port "+port+".");
soc2 = open_sock_tcp(port2, transport:encaps);
if (!soc2) exit(1, "Failed to open a socket on PASV port "+port2+".");

ftp_send_cmd(socket:soc, cmd:'LIST');

r = ftp_recv_line(socket:soc);
is_foscam = FALSE;

if (r =~  "^226")
{
  res = ftp_recv_listing(socket:soc2);
  if ("IPCamera" >< res)
    is_foscam = TRUE;
}

if (is_foscam)
{
  report = 'Nessus was able to log in to the remote Pure-FTPd server using\n' +
           'the hard coded credentials r:r and identify the device as a\n' +
           'vulnerable Foscam C1 IP Camera.';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_HOST_NOT, "Foscam C1 IP Camera");
