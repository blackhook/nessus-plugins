#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11627);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2003-1224", "CVE-2003-1225", "CVE-2003-1226");
  script_bugtraq_id(7563, 7587);

  script_name(english:"WebLogic Multiple Method Cleartext Password Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by information disclosure issues.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running WebLogic 7.0 or 7.0.0.1.

There is a bug in these versions that could allow a local attacker to
recover a WebLogic password if the screen of the WebLogic server is
visible. 

In addition, a local user may be able to view cryptographic secrets,
thereby facilitating cracking of encrypted passwords.");
  # http://web.archive.org/web/20071205054307/http://dev2dev.bea.com/pub/advisory/22
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3912bcb");
  script_set_attribute(attribute:"solution", value:
"Apply Service Pack 3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "weblogic_detect.nasl");
  script_require_keys("www/weblogic");
  script_require_ports("Services/www", 80, 7001);

  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("http.inc");

appname = "WebLogic";
get_kb_item_or_exit("www/weblogic");
port = get_http_port(default:80);
version = get_kb_item_or_exit("www/weblogic/" + port + "/version");
banner = get_http_banner(port:port);

if (" Temporary Patch for CR104520" >< banner) audit(AUDIT_INST_VER_NOT_VULN, appname, version);

if (banner =~ "WebLogic .* 7\.0(\.0\.1)? ")
{
  security_note(port);
  exit(0);
}
audit(AUDIT_INST_VER_NOT_VULN, appname, version);
