#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description) {
  script_id(22306);
  script_version("1.19");

  script_cve_id("CVE-2006-4620");
  script_bugtraq_id(19841);

  script_name(english:"WebAdmin < 3.2.6 MDaemon Account Hijacking");
  script_summary(english:"Checks version of WebAdmin");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that is affected by a
privilege escalation issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running WebAdmin, a web-based remote administration
tool for Alt-N MDaemon. 

According to its banner, the installed version of WebAdmin enables a
domain administrator within the default domain to hijack the 'MDaemon'
account used by MDaemon when processing remote server and mailing list
commands." );
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2006/Sep/38");
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2006/Sep/30");
 script_set_attribute(attribute:"solution", value:
"Upgrade to WebAdmin version 3.2.6 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/09/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/09/04");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2021 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 1000);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:1000);


# Get the version number from the initial page.
res = http_get_cache(item:"/", port:port, exit_on_fail: 1);

# There's a problem if ...
if (
  # it looks like WebAdmin and ...
  '<title>WebAdmin</title>' >< res &&
  '<form name="waForm" action="login.wdm"' >< res &&
  # it's version < 3.2.6
  egrep(pattern:">WebAdmin</A> v([0-2]\..*|3\.([01]\..*|2\.[0-5])) &copy;", string:res)
) security_warning(port);
