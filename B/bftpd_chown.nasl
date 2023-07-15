#TRUSTED 5691dca3da701903f0ed7a5b64f3df6ba5692aa6e04eb39fb3eb17a6d0f1cdd947f99a0b62f71e4bc30c4f48024871f057e494c97621b7bed5a2df875f71c73aa3aebee78437ab8105715dee8899044d46654fe551d065ee226e5cc0323de92b117efd75f1489fb051f33329751607c3a1cacaef0f09c990f15cca772f6fe0073f7fd50e12be5f5876ddabce867cccd26c574ed0251b711d27d10ffaad6d233a7eadc4995cea0ce623407b6055d1177e939538e94d70e948d5fb9ba7fd923e03c8034805efc66fd716085ca40f8fa173f71bb5ea2b1ad5e444ae92072b5f71902100b5fbcbdde472b761404054fbdca2ba7505dd1ba74d3ef2d93965b89738d73752bd5aee2d98266baf6054b5d7eff48f2dfbe09f1ed4f4a48e6a5154725f3771969e173ad290da9d53806d615d3e7745ac6d9633f5ff191fe3b51866bd6510e9e1a33141bb4fad8a6409ce69341d4a82b956ce500efc5e4b7d3d56bca06d4df778e387ecb06439f666b2f2b5f516dfa99f90aaa1043b9e59b334697db06b86ae653746a9cb485054a6ec04ae296e7c267d57556d99f9fcbfac09a35c7ca230624247da54357f748904cd3d43906fb588d35531819b9a26049ccd1ac088c501a86372d8a2da250d113a71b02295783b4e4e2b578b08c3ed6976c2acb3fbe9e64df068790467f5b465aea88d5f4a12dcf26058007b5040ca476d44e55acb46db
#
# (C) Tenable Network Security, Inc.
#


include('compat.inc');


if(description)
{
  script_id(10579);
  script_version("1.42");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/11");

  script_cve_id("CVE-2001-0065", "CVE-2000-0943");
  script_bugtraq_id(2120);

  script_name(english:"bftpd Multiple Command Remote Overflow");
  script_summary(english:"Checks if the remote bftpd daemon is vulnerable to a buffer overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server has a remote buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of bftpd running on the remote host is vulnerable to a
remote buffer overflow attack when issued very long arguments to the
SITE CHOWN command.  A remote attacker could exploit this issue to
crash the FTP server, or possibly execute arbitrary code." );
  script_set_attribute(attribute:"see_also", value:
"https://seclists.org/bugtraq/2000/Dec/222");
  script_set_attribute(attribute:"solution", value:
"Upgrade to bftpd version 1.0.24 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2001-0065");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value: "2000/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value: "2000/12/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK); # mixed
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2000-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl", "ftp_writeable_directories.nasl", "ftp_kibuv_worm.nasl");
  script_require_ports("Services/ftp", 21);
  script_require_keys("Settings/ParanoidReport");

 exit(0);
}

include('ftp_func.inc');

if (report_paranoia < 2)
 audit(AUDIT_PARANOID);

#
# The script code starts here :
#

var login = get_kb_item("ftp/login");
var pass  = get_kb_item("ftp/password");

var port = get_ftp_port(default: 21);

# Connect to the FTP server

if(safe_checks())login = 0;


if(login)
{
 var soc = ftp_open_and_authenticate( user:login, pass:pass, port:port );
 if(soc)
 {
  var req = 'SITE CHOWN AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA A';
  req = req + '\r\n';
  send(socket:soc, data:req);
  var r = ftp_recv_line(socket:soc);
  send(socket:soc, data:'HELP\r\n');
  r = ftp_recv_line(socket:soc, retry: 2);
  if(!r)security_hole(port);
  ftp_close(socket: soc);
  exit(0);
  }
}

var banner = get_ftp_banner(port: port);
if(!banner)exit(1, "No FTP banner on port "+port+".");

if(egrep(pattern:"220.*bftpd 1\.0\.(([0-9][^0-9])|(1[0-3]))",
  	 string:banner)){
	 var data =
	   '\n' +
	   'Note that Nessus detected this issue solely based on the server banner\n';

	 security_report_v4(port:port, extra:data, severity:SECURITY_HOLE);
	 }

