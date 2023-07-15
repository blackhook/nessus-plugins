#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.

#
# Ref : http://www.nessus.org/u?1b1583b1
#
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11628);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_xref(name:"SECUNIA", value:"8778");

  script_name(english:"WebLogic SSL Certificate Chain User Spoofing");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is vulnerable to an impersonation attack.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running WebLogic.

There is a bug in this version that could allow an attacker to perform
a man-in-the-middle attack against the remote server by supplying a
self-signed certificate.

An attacker with a legitimate certificate could use this flaw to 
impersonate any other user on the remote server.");
  script_set_attribute(attribute:"see_also", value:"https://moxie.org/ie-ssl-chain.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to listed versions or higher, as it has been reported to fix 
this vulnerability. Upgrades and/or patches are required as there are 
no known workarounds.

WebLogic Server and Express 7.0 or 7.0.0.1:
- Apply Service Pack 2.
- If using NSAPI Plugin, ISAPI Plugin, or Apache Plugin should upgrade to the 7.0 
Service Pack 2 version of the Plugin.

WebLogic Server and Express 6.1:
- Apply Service Pack 5.
- If using NSAPI Plugin, ISAPI Plugin, or Apache Plugin should upgrade to the 6.1 
Service Pack 5 version of the Plugin.

WebLogic Server and Express 5.1:
- Apply Service Pack 13.
- Apply CR090101_src510 patch.

WebLogic Enterprise 5.1:
- Apply Rolling Patch 145 or later.

WebLogic Enterprise 5.0:
- Apply Rolling Patch 59 or later.

WebLogic Tuxedo 8.1:
- Apply Rolling Patch 12 or later.

WebLogic Tuxedo 8.0:
- Apply Rolling Patch 166 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

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

if ("CR090101" >< banner) audit(AUDIT_INST_VER_NOT_VULN, appname, version);

if(banner =~ "WebLogic .* 5\.") security_warning(port);
else if (banner =~ "WebLogic .* 6\.1 ")
{
  if (banner !~ " SP[5-9]")
  {
    security_warning(port);
    exit(0);
  }
}
else if (banner =~ "WebLogic .* 6\.0 ") 
{
  security_warning(port); # Should upgrade to 6.1
  exit(0);
}
else if (banner =~ "WebLogic .* 7\.0(\.0\.1)? ")
{
  if (banner !~ " SP[2-9]")
  {
    security_warning(port);
    exit(0);
  }
}

audit(AUDIT_INST_VER_NOT_VULN, appname, version);
