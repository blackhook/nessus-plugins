#TRUSTED 355375c852cd17ed5ba5eac96b5dc3397eddfaf2ad3813c43d7567efaf3dea5cb84ddf9d271022fc3d679f6dbccde1f3ed3d82bf68a4e9d2edd3440d0cdb0a596bbf8136c8dec6b9da1a97c19ce34d15c413c630484fc7e356257d77a9c97626071a65e55647afda40beb22a72d76e000328900998b313965f80ac0558553c1e22ac273ff9afdc54240dad74a5fbf6aa6673f9ad122db472e093208446e1dc86135c959071d447be1986571971ff4c99380e5f952f99b03a9af1a8cf9b909c259a6ce520885899ffd0314c850dfe5134c40fea2c0646ea030a51b8c4bcb4d8617818ebc158308322210e51b44f881a863960d2cb68e5ebb3161e458a1dedd946294f28828f94cb73241fd268bc0782fa430b30f5b937c35f2c122a78decfc5dafe98957950dcce5f4c0bd85f0ffb822d7b1e135f8e469cf3de340589b1c0f2c65947d63c292d10343c019129ad15f26c4be2d88d294cbede29670fcf0df7c63fa6d0c02639dea1033a10f05023ef7aa934072fc5079b36447166ccec444bc2f5669f2e7bc148c56a8f046442baa2395e3e2017f8ace2bbfb91465a0727006628b7b1017951011f841d3cec37d48b2ae5942da1b1e95978a72dd9350b09d8cb61199fd0f3d584a88ede7cf17406d7ea83062a243854a9479481bd6c2f3ff59c5d13615bfd69b022e23fe0ecb861329fec3815c018c5ee0a5eebeb26e78cefe6b1
#TRUST-RSA-SHA256 89ed7069a2c8c2aa53813858d4dde8163f8e338d8f9a71068a8f8b50595960326f797d61d67d728c08119e29fb54c741b0b9928b7bfcae55d7b7be39caaae0d59e09435b684ed664eeacf398760f226605fc8411b1773be832a6636dddccda490e34835e5e6933d3fa3ddba73db6e84f425b2012943123e63d32d5b3fb439ae1e2dfaf8bab8cc6f662aad11943f9e7749c7e89e026d07fe98ab1a01124aba035b8eeffaceeb91c42d8ac8abae151823442ebace68aa8ee8deb350fab0c77da476916495042b8eba153ce456df1346a833c9003d5e020753053b93ae4d2c622bfc2c529f05c8a8b7a9e98a3a11433a25253d41b9271dcd6e3c5154b1ad878f900f13b1f56853fb27d2daa46696f6c8321cf9e90d6567091e52c944a6d8636b3ca713416567b1c4146c009b99b73472ea9109c0b9f2ca5c116b87d544e1217d7be75d433eff5dd4e0d74833e4782dc42a821680d55395bcb42dfd710fd3c2417b35f1e7d4c00fb9f9e6396608dfe08c13a2f4da80629238056f82d20eb0ac3e48d14ddf3dd081c943dc2444cfa510110521864fea90d65510aaacc6f18713116b4e58d394399f7b58f59e65bac323d345388d982ef4bcebeacadfe6c9a6e0d75010d287675d3e0d7fe1bd1627a904e5176665c46e114a645387a4e526b07b617669a99611d287ae05bac6215b6969cce57efe5c32a25a127333d1919ad7987e861
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45577);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");
  script_xref(name:"IAVT", value:"0001-T-0763");

  script_name(english:"Atlassian JIRA Detection");

  script_set_attribute(attribute:"synopsis", value:
"An issue tracker is running on the remote web server.");
  script_set_attribute(attribute:"description", value:
"Atlassian JIRA, a web-based issue tracker written in Java, is running
on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.atlassian.com/software/jira");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

##
# A workaround function that allows us to add extra data to installations after they have been registered.
# The added data won't be included in report solely after calling this function.
# @param app_name Name of the application to add extra to - basically always 'Atlassian JIRA' here.
# @param port Port used by the installation we're adding data to.
# @param extra Extra array that should be added to the kb data.
# @param path Web application path that Jira uses
# @return IF_OK if successful, IF_ERROR otherwise
## 
function jira_add_extra(app_name, port, extra, path)
{
  var app_kb_key = make_app_kb_key(app_name:app_name, port:port);
  if (app_kb_key[0] != IF_OK) return IF_ERROR;
  app_kb_key = app_kb_key[1];

  if(empty_or_null(path)) path = '/';

  # Generate install KB key.
  var install_kb_key = make_install_kb_key(app_kb_key:app_kb_key, path:path);
  if (install_kb_key[0] != IF_OK) return IF_ERROR;
  install_kb_key = install_kb_key[1];
  
  add_extra_to_kb(install_kb_key:install_kb_key, extra:extra);
  return IF_OK;
}

##
# A slightly adapted get_install_report from webapp_func.inc.
# It was modified to allow passing Jira edition for each detected instance.
# @param display_name Name of the web application being reported on - basically always 'Atlassian JIRA' here.
# @param installs Installs to report. This should be an array that [add_install] returns.
# @param port Port number of the web server where the app was detected.
# @param jira_editions An array of {path:Jira edition string} containing Jira edition for each detected instance.
# @return A report of installs detected if any were detected, NULL otherwise.
##
function jira_get_report(display_name, installs, port, jira_editions)
{
  var info, version, n, dir, dirs, url, report;

  if (isnull(display_name))
  {
    err_print("jira_get_report() missing required argument 'display_name'.");
    return NULL;
  }
  else if (isnull(port))
  {
    err_print("jira_get_report() missing required argument 'port'.");
    return NULL;
  }

  # Bail out if there's nothing to report (i.e. nothing was detected)
  if (isnull(installs) || max_index(keys(installs)) == 0) return NULL;

  info = "";
  n = 0;

  foreach version (sort(keys(installs)))
  {
    info += strcat('\n  Version : ', version, '\n');
    dirs = split(installs[version], sep:SEPARATOR, keep:FALSE);

    foreach dir (sort(dirs))
    {
      dir = base64_decode(str:dir);

      info += strcat('  URL     : ', build_url(port:port, qs:dir), '\n');
      info += strcat('  Edition : ', jira_editions[dir], '\n');
      n++;
    }
  }

  report = '\nThe following instance';
  if (n == 1) report += ' of ' + display_name + ' was';
  else report += 's of ' + display_name + ' were';
  report += ' detected on the remote host :\n' + info;

  return report;
}

var app = "Atlassian JIRA";
# Put together a list of directories we should check for JIRA in.
var dirs = cgi_dirs();

if (thorough_tests)
{
  dirs = make_list(dirs, "/jira");
  dirs = list_uniq(dirs);
}

# Put together checks for different pages that we can scrape version
# information from.
var checks = make_array();

# This covers older versions.
var regexes = make_list();
regexes[0] = make_list("please notify your JIRA administrator of this problem");
regexes[1] = make_list(">Version *: ([0-9.]+)");
checks["/500page.jsp"] = regexes;

# This covers newer versions.
regexes = make_list();
regexes[0] = make_list(
  '<a +href="http://www\\.atlassian\\.com/software/jira" +class="smalltext" *>Atlassian +JIRA</a *>'
);
regexes[1] = make_list(
  '<meta +name="ajs-version-number" +content="([0-9.]+)" *>',
  '<input +type="hidden" +title="JiraVersion" +value="([0-9.]+)" */>',
  '<span +id="footer-build-information"[^>]*>\\(v([0-9.]+)[^<]+</span *>',
  "Version *: *([0-9.]+)"
);
checks["/login.jsp"] = regexes;

# This covers the REST API for the 4.x series.
regexes = make_list();
regexes[0] = make_list('"baseUrl" *:', '"version" *:', '"scmInfo" *:');
regexes[1] = make_list('"version" *: *"([0-9.]+)"');
checks["/rest/api/2.0.alpha1/serverInfo"] = regexes;

# This covers the REST API for the 5.x series.
checks["/rest/api/2/serverInfo"] = regexes;

# Get the ports that webservers have been found on, defaulting to
# JIRA's default port.
var port = get_http_port(default:8080);

# Find where JIRA is installed.
var installs = find_install(appname:app, checks:checks, dirs:dirs, port:port);

if (isnull(installs))
  audit(AUDIT_WEB_APP_NOT_INST, app, port);

var jira_editions = {};
foreach(var serialized_paths in installs)
{
  foreach(var b64_path in split(serialized_paths, sep:';', keep:FALSE))
  {
    var path = base64_decode(str:b64_path);
    about_page = http_send_recv3(method:'GET', port:port, item:trim(path, rchars:'/') + '/secure/AboutPage.jspa');
    jira_edition = 'Unknown';
    if(!empty_or_null(about_page[2]))
    {
      about_page = about_page[2];
      if ('enabled-feature-keys' >< about_page)
      {
        jira_edition = 'Jira Server';
        if('jira.cluster.monitoring.show.offline.nodes' >< about_page) jira_edition = 'Jira Data Center';
      }
    }

    # Manual workaround - find_install() automatically detects installations and calls register_install(), but it doesn't
    # let us pass extra info, so we need to add it somehow after the installation is saved to KB
    jira_add_extra(app_name:app, port:port, path:path, extra:{'Edition':jira_edition});
    jira_editions[path] = jira_edition;
  }
}

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report = jira_get_report(
    display_name  : app,
    installs      : installs,
    port          : port,
    jira_editions : jira_editions
  );
  # Add edition to the output manually, as the add_extra_to_kb() call only updates the KB, the report is generated separately
  # According to Jira documentation, only one instance can be bound to a single port, so we can safely add edition here without inspecting what the path is
}

security_note(port:port, extra:report);
