#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(22409);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"Claroline Software Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an open source e-learning application
written in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Claroline, an open source, web-based,
collaborative learning environment written in PHP.");
  script_set_attribute(attribute:"see_also", value:"https://www.claroline.net/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:claroline:claroline");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0, php: 1);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/claroline", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # If it looks like Claroline...
  if (
    '<link href="http://www.claroline.net" rel="Copyright" />' >< res ||
    ' class="claroRightMenu"' >< res ||
    ' class="claroToolTitle"' >< res
  ) {
    # Try to get the version number from the README.txt.
    r = http_send_recv3(method:"GET", item:string(dir, "/README.txt"), port:port, exit_on_fail: 1);
    res = r[2];

    pat = "^ +CLAROLINE +(.+) +- +README";
    matches = egrep(pattern:pat, string:res);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          break;
        }
      }
    }

    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";

    set_kb_item(
      name:string("www/", port, "/claroline"),
      value:string(ver, " under ", dir)
    );
    set_kb_item(name:"www/claroline", value: TRUE);
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
      info = string("An unknown version of Claroline was detected on the remote host\nunder the path '", dir, "'.");
    }
    else {
      info = string("Claroline ", ver, " was detected on the remote host under the path\n'", dir, "'.");
    }
  }
  else {
    info = string(
      "Multiple instances of Claroline were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  security_note(port:port, extra:'\n'+info);
}
