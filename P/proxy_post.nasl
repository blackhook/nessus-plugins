#TRUSTED 9f8fb12591480fd6813396844cb742a54d211a29f9381a91d30aa6e3c7950f9f58566ecb0bd3721d0029fdee0e3e7639f8efbfff694cf03e5ebf1071beb6e4a6dc1b22f8ebd399de42663405b962a672984c8135c0b025442b8ea74575ca4905f24ef8e1593d319cd0df7f813f571a8a4464a413691726a2b91e7ce7b03a4b6ea39918ed1475b24827a40053886b541dcbd0bc70605ccc2d519e197830924b91a670263afe8dd96dfc86cd9b278ef2824584aa5d7b5be4f5ffff8d83addb7a6c975a6227c381018a2ff6e25ebeea4e4d19b4307fde42ade985252f78214d11bc1e6e67aaa762432f21099170825e843f43afbd40987ac3b80d5a3daf24c9508c716f903f48bd777b416c630bf8ff3136e96e8f385429a71395ade5d06ece14a3570b5a1417ddf6faabe5ebb589eb70f880291077864e7f7285d2e57754cabbf31232248ddc51a7f50cb6f6cec11759995f59c8f0dc3f8fe482cd5d244e976d55017ff1a08f60870a8835f91d8477f0752043ded898f733956d26733e345107a6694c5a7915332a05b2a9b558b146fb39aee3dfc27d655466af7767e65d8327efbf33c6f1cfb1886fc90459bc27ba51cb33d8f6873e425dfd4c006c403548f462d55064541ea9fd6f32dc1411eeb91bf116ac6d2436e8e735cc617b795942738c559650c9b2ff8c25503c6fde19edd399af772ccede5e3c3f5368aff4a4988174
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10194);
 script_version("1.23");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/13");

 script_name(english: "HTTP Proxy POST Request Relaying");

 script_set_attribute(attribute:"synopsis", value:
"Interactive sessions can be open through the HTTP proxy." );
 script_set_attribute(attribute:"description", value:
"The proxy allows the users to perform POST requests such as

	POST http://cvs.nessus.org:21

without any Content-length tag.

This request may give an attacker the ability to have an interactive
session.

This problem may allow attackers to go through your firewall, by
connecting to sensitive ports like 23 (telnet) using your proxy, or it
can allow internal users to bypass the firewall rules and connect to
ports they should not be allowed to.

In addition to that, your proxy may be used to perform attacks against
other networks." );
 script_set_attribute(attribute:"solution", value:
"Reconfigure your proxy so that only the users of the internal network
can use it, and so that it can not connect to dangerous ports (1-1024)." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
 script_set_attribute(attribute:"cvss_score_source",value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of vulnerability.");

script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Determines if we can use the remote web proxy against any port");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2021 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");
 script_dependencies("find_service1.nasl", "proxy_use.nasl", "no404.nasl");
 script_require_keys("Proxy/usage");
 script_require_ports("Services/http_proxy", 8080);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

var port = get_kb_item("Services/http_proxy");
if(!port) port = 3128;
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");

var usable_proxy = get_kb_item("Proxy/usage");
if (! usable_proxy) exit(0, "The host does not appear to be running an HTTP proxy.");

var non404 = get_kb_list("www/no404/" + port);

if (!isnull(non404)) audit(AUDIT_HOST_NOT, "affected");

var rq = http_mk_proxy_request(scheme: "http", method: "POST", item: "/", version: 10, host: get_host_name(), port: 21);
    rq['Content-Length'] = NULL;	# Just in case we change the API one day

var r = http_send_recv_req(port: port, req: rq);
if (isnull(r)) exit(0);
if (r[0] =~ "^HTTP/1\.[01] (200|503) ") security_warning(port);
