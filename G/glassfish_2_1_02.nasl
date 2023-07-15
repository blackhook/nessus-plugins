#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(39330);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/05");
  
  script_bugtraq_id(35217);

  script_name(english:"Sun GlassFish Enterprise < 2.1 Patch 02 Denial of Service");
  script_summary(english:"Checks the Version of Sun GlassFish Enterprise Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a local denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Sun GlassFish Enterprise
Server earlier than Sun GlassFish Enterprise Server 2.1 with Patch 02.
Such versions are reportedly affected by a local denial 
of service vulnerability in the HTTP Engine and administration 
interface. A local attacker could exploit this issue to crash the 
affected service.");
  script_set_attribute(attribute:"see_also", value:"https://download.oracle.com/sunalerts/1020443.1.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sun GlassFish Enterprise Server 2.1 with Patch 02 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/09");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("glassfish_detect.nasl");
  script_require_keys("www/glassfish");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("glassfish.inc");

#
# Main
#

# Check for GlassFish
get_kb_item_or_exit('www/glassfish');

port = get_glassfish_port(default:8080);

ver = get_kb_item_or_exit("www/" + port + "/glassfish/version");
source = get_kb_item_or_exit("www/" + port +"/glassfish/source");

if (!empty_or_null(ver) &&
  ((ver =~ "^2\.[01]$") || (ver =~ "^2\.1\.01$")))
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "According to its banner, ", source, " is installed on the remote host.\n"
    );
    security_note(port:port, extra:report);
  }
  else security_note(port:port);
  exit(0);
}

audit(AUDIT_LISTEN_NOT_VULN, "GlassFish Server", port);
exit(0);
