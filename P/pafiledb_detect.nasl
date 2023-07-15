#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(17327);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"paFileDB Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a download management script written in
PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running paFileDB, a web-based download management
script written in PHP.

Note that the software's homepage, formerly at
http://www.phparena.net/pafiledb.php, no longer exists, and the
associated domain is parked, suggesting that the software is no longer
supported.");
  # http://web.archive.org/web/20050714012644/http://www.phparena.net/pafiledb.php
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?664be9c0");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php_arena:pafiledb");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/pafiledb", "/dl", "/downloads", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  r = http_send_recv3(method:"GET", item:string(dir, "/pafiledb.php"), port:port);
  if (isnull(r)) exit(0, "The web server did not answer");
  res = r[2];

  # If it's paFileDB.
  if ("powered by paFileDB" >< res) {
    if (dir == "") dir = "/";

    # Identify the version number.
    pat = "powered by paFileDB (.+)(\. Visit|<br>)";
    matches = egrep(pattern:pat, string:res);
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = ver[1];
        break;
      }
    }
    if (isnull(ver)) ver = "unknown";

    set_kb_item(
      name:string("www/", port, "/pafiledb"),
      value:string(ver, " under ", dir)
    );
    set_kb_item(name: "www/pafiledb", value: TRUE);
    installations[dir] = ver;
    ++installs;

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}


# Report any instances found unless Report verbosity is "Quiet".
if (installs && report_verbosity > 0) {
  if (installs == 1) {
    foreach dir (keys(installations)) {
      # empty - just need to set 'dir'.
    }
    if (ver == "unknown") {
      info = string("An unknown version of paFileDB was detected on the remote\nhost under the path '", dir, "'.");
    }
    else {
      info = string("paFileDB ", ver, " was detected on the remote host under\nthe path '", dir, "'.");
    }
  }
  else {
    info = string(
      "Multiple instances of paFileDB were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  security_note(port:port, extra:'\n'+info);
}
