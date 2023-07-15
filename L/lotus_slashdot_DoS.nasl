#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Date:  Fri, 7 Dec 2001 14:23:10 +0100
# From: "Sebastien EXT-MICHAUD" <Sebastien.EXT-MICHAUD@atofina.com>
# Subject: Lotus Domino Web server vulnerability
# To: bugtraq@securityfocus.com

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11718);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2001-0954");
  script_bugtraq_id(3656);

  script_name(english:"Lotus Domino /./ Request Database Locking DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service 
vulnerability.");
  script_set_attribute(attribute:"description", value:
"It might be possible to lock out some Lotus Domino databases by 
requesting them through the web interface with a special request
containing a '/./' string in the URL path.

This attack is only efficient on databases that are not used by
the server.

*** Note that no real attack was performed, 
*** so this may be a false positive.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Lotus Domino 5.0.9 or later, as this reportedly fixes
the issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lotus:domino");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2003-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "find_service1.nasl", "http_login.nasl", "httpver.nasl", "no404.nasl");
  script_require_keys("www/domino");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);


b = get_http_banner(port: port, exit_on_fail: 1);
if(egrep(pattern: "^Server: Lotus-Domino/(Release-)?(5\.0\.[0-8][^0-9])", string:b))
  security_warning(port);
