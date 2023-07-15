#TRUSTED 71bf7e8a87626e9333ab734a69040f9ab22b22819336ca5cff40161c0db7f68971ec35f73b2a1e8ce8dde5eb7539d9ed96e7429889dbe27308aaa7f913a2d9ba8bea89fff4f3ea889eb710879a7abccaa5405b898fdb40622526ff052978d9342177a9711755d7ad6b989ee7d53d43bfd00df48dfb5a4dcaeda06686733617ca084d8ddc818cfe5412f52ab0d372561a1cb57a4e547d19b61aaf2996ff3b07373704fdbc6134fe5d7c40cc187871e7ba3f8450c33fd92a2c789be51814fc33b6436bb0d71afeef394654552f41cab8f2a1c7b2739a21d6234f5cfada5006f172c704d5de17e3be53f1a847cc40a45eed89f0294f1c149e81485547a74c307534c8a8d2deb38f9989bac0650ec7699ee32115e4521321592f91a31464aa8116b5284e87f918ad919b86c00efab4281e492dd60afa088646f569748084a47cc405e605af47e992202619611665a9a3cf2fbbbab2384594489d2e825b005feedfa3b022aff659da347a96545a0a6f8e007551e736c692928270b7e620ce6be3a21786e62235dacbdeccd75f6ea408b6f19de55f0485b5a09abbdf31ff6ebde724bd39ed3f2b90ed79cba5476bda0dbfd500d6c919d9ac3069aa7fcc3e653eee44fab64c0a1143827134daebdd0100fcf9d31acdb32bc14f1c36eb3c7284653b3c1815e5df3d4d6794d03892d0715a3ae8b35e9eefb43b663ed4dd58e2a2d206b838
###
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10088);
 script_version("1.37");
 script_cvs_date("Date: 2018/10/10 14:50:53");

 script_cve_id("CVE-1999-0527");
 script_xref(name:"CERT-CC", value:"CA-1993-10");

 script_name(english:"Anonymous FTP Writable root Directory");
 script_summary(english:"Attempts to write on the remote root dir.");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server allows write access to the root directory.");
 script_set_attribute(attribute:"description", value:
"It is possible to write on the root directory of the remote anonymous
FTP server. This allows an attacker to upload arbitrary files which
can be used in other attacks, or to turn the FTP server into a
software distribution point.");
 script_set_attribute(attribute:"solution", value:
"Restrict write access to the root directory.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0527");

 script_set_attribute(attribute:"vuln_publication_date", value:"1997/10/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 1999-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"FTP");

 script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#
include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('ftp_func.inc');

login = get_kb_item_or_exit("ftp/login");
password = get_kb_item("ftp/password");

port = get_ftp_port(default: 21);

vuln = FALSE;

soc = ftp_open_and_authenticate( user:login, pass:password, port:port );
if (!soc)
  exit(1, "Cannot authenticate on port "+port+".");

send(socket:soc, data: 'CWD /\r\n');
a = recv_line(socket:soc, length:1024);

report = 'The command "CWD /" produced the following result :\n\n' +
         a +'\n' +
         '\n----------------------------------------------------\n';

ftp_pasv(socket:soc);

send(socket:soc, data: 'STOR nessus_test\r\n');
r = recv_line(socket:soc, length:3);

report += 'The command "STOR .nessus_test" produced the following result :\n\n' +
         r +'\n';

if (r == "425"|| r == "150")
{
  vuln = TRUE;
  send(socket:soc,data: 'DELE nessus_test\r\n');
}

ftp_close(socket: soc);

if (vuln)
{
  replace_kb_item(name:"ftp/"+port+"/writable_root", value:"/");
  set_kb_item(name:"ftp/"+port+"/writable_root", value:TRUE);
  set_kb_item(name:"ftp/writable_root", value:TRUE);

  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "FTP", port);
