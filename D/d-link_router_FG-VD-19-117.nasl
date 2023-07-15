#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166889);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/03");

  script_name(english:"D-Link Routers Unauthenticated RCE (CVE-2019-16920)");

  script_set_attribute(attribute:"synopsis", value:
"The remote router is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote D-Link router is affected by a remote code execution vulnerability. Unauthenticated remote code execution
occurs in D-Link products such as DIR-655C, DIR-866L, DIR-652, and DHP-1565. The issue occurs when the attacker sends
an arbitrary input to a PingTest device common gateway interface that could lead to common injection. An attacker who
successfully triggers the command injection could achieve full system compromise. Later, it was independently found that
these are also affected: DIR-855L, DAP-1533, DIR-862L, DIR-615, DIR-835, and DIR-825.

Note that Nessus has not tested for this issue but has instead relied only on the router's self-reported model.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/zeroday/FG-VD-19-117");
  script_set_attribute(attribute:"see_also", value:"https://www.kb.cert.org/vuls/id/766427");
  script_set_attribute(attribute:"see_also", value:"https://www.seebug.org/vuldb/ssvid-98079");
  script_set_attribute(attribute:"solution", value:"Upgrade to a supported device.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16920");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 Tenable Network Security, Inc.");

  script_dependencies("d-link_router_detect.nasl");
  script_require_keys("www/d-link", "d-link/model");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');

var model = toupper(get_kb_item_or_exit('d-link/model'));
if (
   model !~ "^DIR-655$" &&
   model !~ "^DIR-866L$" &&
   model !~ "^DIR-652$" &&
   model !~ "^DHP-1565$" &&
   model !~ "^DIR-855L$" &&
   model !~ "^DAP-1533$" &&
   model !~ "^DIR-862L$" &&
   model !~ "^DIR-615$" &&
   model !~ "^DIR-835$" &&
   model !~ "^DIR-625$"
  )
 audit(AUDIT_HOST_NOT, 'an affected D-Link model');

var port = get_http_port(default:80, embedded:1);
var items = make_array('Model', model, 'Solution', 'Upgrade to a supported device');
var order = make_list('Model', 'Solution');
var report = report_items_str(report_items:items, ordered_fields:order);

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
