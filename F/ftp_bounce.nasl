#TRUSTED 758045371c3da5668db1145332c36f26e2ddf628a8fce9646d97e01690d34a135f38db469e4ddb596543406391d1dbf3d69c1efa544be2dfbbe1a7ecc7254b625ccb1bfeee076e75eea921229878b6ccbc0152c36d1c36f4ea984ed12f04f742c28fcbe11299dffd12bd76f778bc581c828459f8d3671ff2fd608283e9da06284da254253988d12b8a940820f0b3f9c93b0ca1e9cfd3b1d3d8c8f6e82301999f2015492322943b94d0fb7485e16bbf32829d249c263ab6ff2b4c7ece618267740bfef781de81ea1badc3cb09715719288809c95e39aa2f5b2d5156794058857614f7888ed7960b6b6f2f2e6ee3360eaaa64cc38bba2ae8ad0a6abd7f0a14d58b397ec0aab0b198c77f0a5c93e0da878ecc85d3f65c5b67c9b5c2d87ca2447769ef5e4bea059a6cf10c209de7b16e45bf90440eac79fa7759d4874b2347fdc6b080570a2a89bf10213541e8c07793987ad9c4f00be17279678ddc073bd415bab2c908c8669692abae5ee7a6e1e901f879389a0592bbe8ade97bce272c2d0397b8d776c989703babfb9e2022fff93d6e3109fca6016f78b5894e970a7d847ddab8a24423bc71b6fd346253937b32c315c2297cdd26a83bfbe620f98ff837d3f69a259f95f2c192cf6bab1a6ffb973170d070a6a279e330a089f5cf2138917aa30739192d544cfb8403b844c3af898439313fc2b1c9a0ac9da9579dacc429c7b2e4
###
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10081);
 script_version("1.49");
 script_cvs_date("Date: 2018/11/15 20:50:22");

 script_cve_id("CVE-1999-0017");
 script_bugtraq_id(126);
 script_xref(name:"CERT-CC", value:"CA-1997-27");

 script_name(english:"FTP Privileged Port Bounce Scan");
 script_summary(english:"Checks if the remote ftp server can be bounced");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is vulnerable to a FTP server bounce attack.");
 script_set_attribute(attribute:"description", value:
"It is possible to force the remote FTP server to connect to third
parties using the PORT command. 

The problem allows intruders to use your network resources to scan
other hosts, making them think the attack comes from your network.");
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/1995/Jul/46");

 script_set_attribute(attribute:"solution", value:"See the CERT advisory in the references for solutions and workarounds.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0017");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"1995/07/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_family(english:"FTP"); 
 script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl", "ftp_kibuv_worm.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 script_exclude_keys("ftp/ncftpd");
 exit(0);
}

#
# The script code starts here :
#
include('global_settings.inc');
include('misc_func.inc');
include('ftp_func.inc');

port = get_ftp_port(default: 21);

login = get_kb_item_or_exit("ftp/login");
password = get_kb_item("ftp/password");

soc = ftp_open_and_authenticate( user:login, pass:password, port:port );
if ( soc )
 {
  ip = get_host_ip();
  last = ereg_replace(string:ip,
  		    pattern:"[0-9]*\.[0-9]*\.[0-9]*\.([0-9]*)$",
		    replace:"\1");
  last = (int(last) + 42) % 256;
  ip = '169,254,' + string( rand() % 256 ) + ',' + string(rand() % 256);
  ip = ereg_replace(string:ip, pattern:"\.", replace:",");
  ip = ereg_replace( pattern:"([0-9]*,[0-9]*,[0-9]*,)[0-9]*$",
  			replace:"\1",
			string:ip);
  ip = string(ip) + string(last);
  h  = str_replace(string:ip, find:',', replace:'.');
  command = 'PORT ' + ip + ',42,42\r\n';
  send(socket:soc, data:command);
  code = ftp_recv_line(socket:soc);
	close(soc);
  if ( ! code ) {
	exit(0);
  }
  code = str_replace(string:code, find:'\r', replace:'');
  p = 42*256+42;
  if ( code =~ "^200" )
   security_hole(port:port, extra:'The following command, telling the server to connect to ' + h + ' on port ' + p + ':\n\n' + ( command - '\r')  + '\nproduced the following output:\n\n' + code);
 }
