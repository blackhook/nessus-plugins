#%NASL_MIN_LEVEL 70300
#
# This script was written by Matt Moore <matt@westpoint.ltd.uk>
# Majority of code from plugin fragment and advisory by H D Moore <hdm@digitaloffense.net>
#
# no relation :-)
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10956);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-1999-0739");
  script_bugtraq_id(167);
  script_xref(name:"MSFT", value:"MS99-013");
  script_xref(name:"MSKB", value:"231368");
  script_xref(name:"MSKB", value:"231656");

  script_name(english:"Microsoft IIS / Site Server codebrws.asp Arbitrary Source Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"Some files may be read on the remote host.");
  script_set_attribute(attribute:"description", value:
"Microsoft's IIS 5.0 web server is shipped with a set of
sample files to demonstrate different features of the ASP
language. One of these sample files allows a remote user to
view the source of any file in the web root with the extension
.asp, .inc, .htm, or .html.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/1999/ms99-013");
  script_set_attribute(attribute:"solution", value:
"Apply the patch referenced above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"1999/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/05/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2002-2022 Matt Moore / HD Moore");

  script_dependencies("find_service1.nasl", "no404.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_require_keys("www/ASP");
  script_require_ports("Services/www", 80);

  exit(0);
}

# Check simpy tests for presence of Codebrws.asp. Could be improved
# to use the output of webmirror.nasl, and actually exploit the vulnerability.

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80, embedded:TRUE);
if ( ! can_host_asp(port:port) ) exit(0);


req = http_get(item:"/iissamples/sdk/asp/docs/codebrws.asp", port:port);
res = http_keepalive_send_recv(data:req, port:port);
if ("View Active Server Page Source" >< res)
{
    security_warning(port);
}
