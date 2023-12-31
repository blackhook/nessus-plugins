#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55931);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2011-0807");
  script_bugtraq_id(47438);
  script_xref(name:"EDB-ID", value:"17615");

  script_name(english:"Oracle GlassFish Server Administration Console GET Request Authentication Bypass");
  script_summary(english:"Bypasses authentication and accesses a page which permits code execution.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server has an authentication bypass vulnerability
that may permit code execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of GlassFish Server running on the remote host has an
authentication bypass vulnerability. The server fails to enforce
authentication on HTTP requests that contain lower case method names
(e.g. 'get').

A remote, unauthenticated attacker could exploit this to upload and
execute arbitrary code."
  );
  #https://www.oracle.com/technetwork/topics/security/cpuapr2011-301950.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93e12960");
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.zerodayinitiative.com/advisories/ZDI-11-137/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to GlassFish Server 3.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-0807");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun/Oracle GlassFish Server Authenticated Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/17");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("glassfish_console_detect.nasl");
  script_require_keys("www/glassfish", "www/glassfish/console");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("glassfish.inc");
include("http.inc");

#
# Main
#

# Check GlassFish & GlassFish Admin Console
get_kb_item_or_exit('www/glassfish');
get_kb_item_or_exit('www/glassfish/console');

# By default, GlassFish's administration console listens on port 4848.
port = get_glassfish_console_port(default:4848);

# Get the previously-detected version of GlassFish so we know which
# page to request.
version = get_kb_item_or_exit("www/" + port + "/glassfish/version");
if (version =~ "^[29]")
  url = "/applications/upload.jsf";
else if (version =~ "^3")
  url = "/common/applications/uploadFrame.jsf";
else
  exit(0, "The Oracle GlassFish server on port " + port + " is version " + version + " and thus is not affected.");

# Try to access the page with a lowercase HTTP request method.
res = get_glassfish_res(
  method       : "get",
  port         : port,
  url          : url,
  exit_on_fail : TRUE
);

if (res[2] !~ "<title>Deploy.*Applications.*Modules</title>")
  exit(0, "The Oracle GlassFish server on port " + port + " is not vulnerable.");

if (report_verbosity > 0)
{
  report =
    '\nNessus was able to exploit the issue using the following request :' +
    '\n' +
    '\n' + http_last_sent_request();

  security_hole(port:port, extra:report);
}
else security_hole(port:port);
