#TRUSTED b09aace851077b1cbe369836c5cbccce1a1b5e89a855e303a07f76d31c706abc824cc7ab27a25a7bb65f7a9505490f6f35e6cdad53fc1394ff36fd471100cc6055573ff0c32e1fedc2ff48826d829acdecec185edcd1f3d360dea4d7d258fab4d5a89b1d7e77825aeabfc036828dffc1ed3e5e857509adc852d6591e57e034a9b063b6cc09fab7ce4e2e5060a2b9a8adffbb6b77caba0219b4b4c0999ac5fcf2556bdee4ac101e4da38c96499ac9e89ef4f897edfeb7ace3ceab9bad8885a5e074c36238f6040efc32fad37c0086cd58c11b91a03877659973a903ba92ccefe5605b2df88593477c12dbddcb94be8e7c2f6cdd1b53913b19d304e15b5360930b61c259cc93eeb367fda7021bc0e7fff6ee47077d5d1aacff4c23de715ba96214071976cb45aa4f66494248ab4cad6fc91075022c9135a0a8b3cf2eb2a0a838f00bc295fa9fe2ed104ca591b2e46ecadaae6c2234cb60430fc066054e191e50832e30db77a7d1e77b602acea1b77a79d119c76e24ea3b167e31a153ff4f61706b298ddcec9f2d430b3ab0312a09438c6f64cff0d9522cf11b5188b642fb004d7c1836ac460b3a8cd065d4df4ebed93e8791814fa6c5f15e4614790aeefd36b456b8a5a4c4bb2c7e80fed19bb6b64217a24d661def714ce8e48a57791eb25a88162057cf1c90f3cb05c8e72e0cb9543ffe0e9d1f4a8c67ffbc790f28784d44a903
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10556);
  script_version("1.45");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/11");

  script_cve_id("CVE-2001-0450");
  script_bugtraq_id(301);

  script_name(english:"Broker FTP Multiple Command Arbitrary File/Directory Manipulation");
  script_summary(english:"Attempts to get the listing of the remote root dir");

  script_set_attribute(attribute:"synopsis", value:"The remote FTP server has a directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"Broker FTP appears to be running on the remote host. This version has
a directory traversal vulnerability that allows a remote attacker to
view and delete files outside of the FTP root directory.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2001/Mar/26");
  script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of Broker FTP.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2001-0450");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/11/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2000-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
  script_require_keys("ftp/login", "Settings/ParanoidReport");
  script_exclude_keys("ftp/ncftpd", "ftp/msftpd");
  script_require_ports("Services/ftp", 21);

 exit(0);
}

include("ftp_func.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);

var port = get_ftp_port(default: 21);

var soc = ftp_open_and_authenticate( user:"anonymous", pass:"nessus@nessus.org", port:port );
if(soc)
{
 var p = ftp_pasv(socket:soc);
 var soc2 = open_sock_tcp(p, transport:get_port_transport(port));
 if(soc2)
 {
  var s = 'LIST /\r\n';
  send(socket:soc, data:s);
  var r = ftp_recv_line(socket:soc);
  if(egrep(pattern:"^150 ", string:r))
  {
      var listing1 = ftp_recv_listing(socket:soc2);
  }
  close(soc2);
  r = ftp_recv_line(socket:soc);

  p = ftp_pasv(socket:soc);
  soc2 = open_sock_tcp(p, transport:get_port_transport(port));
  if ( ! soc2 ) exit(1, "Cannot connect to TCP port "+p+".");


  s = 'LIST C:\\\r\n';
  send(socket:soc, data:s);
  r = ftp_recv_line(socket:soc);
  if(egrep(pattern:"^150 ", string:r))
  {
      r = ftp_recv_listing(socket:soc2);
      if(r && ( listing1 != r ) )
      {
	    if("No such file or directory" >< r)exit(0);

        var extra = 'It was possible to get the listing of the remote root\n'+
        'directory by issuing the command\n\n'+
        'LIST C:\\\n'+
        'Which displays :\n'+
        string(r) + '\n';
        security_report_v4(port:port, extra:extra, severity:SECURITY_HOLE);
      }
  }
 close(soc);
 close(soc2);
 }
}

