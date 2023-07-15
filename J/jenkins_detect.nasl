#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65054);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");
  script_xref(name:"IAVT", value:"0001-T-0638");

  script_name(english:"Jenkins Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a job scheduling / management system.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts Jenkins, a job scheduling / management
system and a drop-in replacement for Hudson.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/index.html");
  script_set_attribute(attribute:"see_also", value:"https://www.cloudbees.com/jenkins/about");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("http.inc");
include("install_func.inc");
include("spad_log_func.inc");

var appname = "Jenkins";
var port = get_http_port(default:8080, embedded:FALSE);

var dirs = make_list("/", cgi_dirs());
if (thorough_tests)
  dirs = list_uniq(make_list("/jenkins", dirs));

var dir = {};
var installs = 0;
var installed, version, edition, hudson_version, is_LTS;

foreach dir (dirs)
{
  installed = FALSE;
  version = NULL;
  edition = NULL;
  hudson_version = UNKNOWN_VER;
  is_LTS = FALSE;
  
  var rootres = NULL;

  if (empty_or_null(dir)) continue;

  # sanity check root for X-Jenkins header
  rootres = http_send_recv3(item:dir, port:port, method:"GET", exit_on_fail:TRUE);
  spad_log(message:'rootres: ' + obj_rep(rootres) + '\n');
  if (empty_or_null(rootres) || ("Jenkins" >!< rootres[1] && "Jenkins" >!< rootres[2]))
  {
    spad_log(message:'"Jenkins" not found in header for ' + dir + '\n');
    continue;
  }

  # attempt modern detection using login page (first)
  var loginres = http_send_recv3(
    item:dir + "/login",
    port:port,
    method:"GET",
    exit_on_fail:TRUE
  );
  spad_log(message:'loginres: \n' + obj_rep(loginres) + '\n');

  if (empty_or_null(loginres) || ("HTTP/1.1 200" >!< loginres[0]) || ("X-Jenkins" >!< loginres[1]))
  {
    spad_log(message:'Jenkins /login not found for ' + dir + '\n');
    continue;
  }

  if ("X-Jenkins:" >< loginres[1] && '<span class="jenkins_ver">' >< loginres[2])
  {
    # modern detection
    spad_log(message:'modern detection\n');

    # grab version from header
    var item = pregmatch(pattern:"X-Jenkins: ([0-9.]+)", string: loginres[1]);
    if (!empty_or_null(item)) version = item[1];
  
    # grab hudson version from header
    item = pregmatch(pattern:"X-Hudson: ([0-9.]+)", string: loginres[1]);
    if (!empty_or_null(item)) hudson_version = item[1];

    # figure out what edition this is
    if ("CloudBees Jenkins Operations Center" >< loginres[2] || "CloudBees+Jenkins+Operations+Center" >< loginres[2])
      edition = "Operations Center";
    else if ("CloudBees Jenkins Enterprise" >< loginres[2] || "CloudBees+Jenkins+Enterprise" >< loginres[2])
      edition = "Enterprise";
    else if ("Jenkins ver. " >< loginres[2])
      edition = "Open Source"; # might be LTS, checks that later

    spad_log(message:'version: ' + version + '\n');
    spad_log(message:'edition: ' + edition + '\n');
    if (!empty_or_null(version) && !empty_or_null(edition))
    {
      # modern detection succeeded
      # still need to set some KBs for legacy plugins

      if (edition != "Operations Center")
      {
        # legacy plugins don't know about ops center so will FP these
        # thinking they are Open Source if we include them
        # legacy KBs
        set_kb_item(name:'www/Jenkins', value:TRUE);
        set_kb_item(name:"www/Jenkins/"+port+"/Installed", value:TRUE);
        set_kb_item(name:"www/Jenkins/" + port + "/JenkinsVersion", value:version);
        set_kb_item(name:"www/Jenkins/" + port + "/HudsonVersion", value:hudson_version);
      }

      if (edition == "Enterprise")
      {
        # legacy KBs
        set_kb_item(name:"www/Jenkins/"+port+"/enterprise/Installed", value:TRUE);
        set_kb_item(name:"www/Jenkins/"+port+"/enterprise/CloudBeesVersion", value:version);
      }

      if (edition == "Open Source")
      {
        # legacy KBs
        # All LTS releases are max_index >= 3
        # All non-LTS releases are max_index == 2, EXCEPT one non-LTS
        # release : 1.395.1, so do not mark that one as LTS
        if (
          (max_index(split(version, sep:".", keep:FALSE)) >= 3) &&
          version != '1.395.1'
        )
        {
          is_LTS = TRUE;
          set_kb_item(name:"www/Jenkins/" + port + "/is_LTS", value:TRUE);
          # if it's LTS, we set it to LTS
          edition = "Open Source LTS";
        }
      }

      # register the install
      installs++;
      register_install(
        app_name : appname,
        vendor : 'CloudBees',
        product : 'Jenkins',
        path     : dir,
        version  : version,
        port     : port,
        cpe      : "cpe:/a:cloudbees:jenkins",
        webapp   : TRUE,
        extra    : make_array("Edition", edition, "Hudson Version", hudson_version, "LTS", is_LTS)
      );

      if (thorough_tests)
        continue;
      else
        break;

    }
  }

  ##
  #  attempt modern detection specific to Cloudbees Jenkins Enterprise
  #   using the "/" page  (not the "/login" page)
  ##
  if ( "X-Jenkins:" >< rootres[1] &&
       '<span class="jenkins_ver">' >< rootres[2] &&
       "CloudBees Jenkins Enterprise" >< rootres[2]  )
  {
    # modern detection
    spad_log(message:'modern Cloudbees detection\n');

    version = NULL;
    edition = NULL;

    # grab version from header
    item = pregmatch(pattern:"CloudBees Jenkins Enterprise ([0-9]+\.[0-9.]+)", string: rootres[2]);
    if (!empty_or_null(item))
    {
      edition = "Enterprise";
      version = item[1];
    }

    # grab hudson version from header
    item = pregmatch(pattern:"X-Hudson: ([0-9.]+)", string: rootres[1]);
    if (!empty_or_null(item)) hudson_version = item[1];

    spad_log(message:'version: ' + version + '\n');
    spad_log(message:'edition: ' + edition + '\n');
    if (!empty_or_null(version) && !empty_or_null(edition))
    {
      # modern detection succeeded
      # still need to set some KBs for legacy plugins

      set_kb_item(name:'www/Jenkins', value:TRUE);
      set_kb_item(name:"www/Jenkins/" + port + "/Installed", value:TRUE);
      set_kb_item(name:"www/Jenkins/" + port + "/JenkinsVersion", value:version);
      set_kb_item(name:"www/Jenkins/" + port + "/HudsonVersion", value:hudson_version);
      set_kb_item(name:"www/Jenkins/" + port + "/enterprise/Installed", value:TRUE);
      set_kb_item(name:"www/Jenkins/" + port + "/enterprise/CloudBeesVersion", value:version);
      set_kb_item(name:"www/Jenkins/" + port + "/is_LTS", value:TRUE);

      # register the install
      installs++;
      register_install(
        app_name : appname,
        vendor : 'CloudBees',
        product : 'Jenkins',
        path     : dir,
        version  : version,
        port     : port,
        cpe      : "cpe:/a:cloudbees:jenkins",
        webapp   : TRUE,
        extra    : make_array("Edition", edition, "Hudson Version", hudson_version, "LTS", TRUE)
      );

      if (thorough_tests)
        continue;
      else
        break;

    }
  }


  # fall back to legacy detection if modern detection fails
  spad_log(message:'legacy detection\n');
  
  var res = rootres;
  var jenkins_ver, hudson_ver, cloudbees_ver;

  installed     = FALSE;
  jenkins_ver   = NULL;
  hudson_ver    = NULL;
  cloudbees_ver = NULL;
  is_LTS        = FALSE;

  # check server headers first
  if ( (("200 OK" >!< loginres[0]) || ("HTTP/1.1 200" >!< loginres[0])) && ("X-Jenkins:" >< res[1]) || ("X-Hudson:" >< res[1]) )
  {
    spad_log(message:'X-Jenkins or X-Hudson found\n');
    installed = TRUE;

    # Check for open source Jenkins
    item = pregmatch(pattern:"X-Jenkins:\s*([0-9.]+)(-SNAPSHOT)?[ \r\n]", string: res[1]);
    if (!empty_or_null(item)) jenkins_ver = item[1];

    # Check for enterprise Jenkins (by CloudBees)
    item = pregmatch(pattern:"X-Jenkins:\s*([0-9.]+)(-SNAPSHOT)? \(Jenkins Enterprise by CloudBees ([0-9.]+)\)[ \r\n]", string: res[1]);
    if (!empty_or_null(item))
    {
      jenkins_ver = item[1];
      cloudbees_ver = item[3];
    }
 
    item = pregmatch(pattern:"X-Hudson:\s*([0-9.]+)[ \r\n]", string: res[1]);
    if (!empty_or_null(item)) hudson_ver = item[1];
  }

  # check alternate server header seen in Jenkins 2.60.1
  if ("Jenkins-Version" >< res[1])
  {
    spad_log(message:'Jenkins-Version found\n');
    installed = TRUE;

    # Check for open source Jenkins
    item = pregmatch(pattern:"Jenkins-Version:\s([0-9]+\.[0-9.]+)", string: res[1]);
    if (!isnull(item)) jenkins_ver = item[1];

    item = pregmatch(pattern:"X-Hudson:\s*([0-9.]+)[ \r\n]", string: res[1]);
    if (!isnull(item)) hudson_ver = item[1];
  }


  # check result body
  var match, link;

  if (!installed)
  {
    # Check for meta redirect to login page and manually follow if found
    if ("<meta http-equiv='refresh'" >< res[2])
    {
      match = pregmatch(pattern:"content='1;url=(.*)'/>", string:res[2]);
      if (!empty_or_null(match))
      {
        link = match[1];

        res = http_send_recv3(
          method : "GET",
          port   : port,
          item   : link,
          exit_on_fail : TRUE
        );
      }
    }

    # nb: this works for enterprise Jenkins as well
    if ( ("Welcome to Jenkins!" >< res[2] && "<title>Dashboard [Jenkins]</title>" >< res[2]) ||
      ("<title>Jenkins</title>" >< res[2] && "images/jenkins.png" >< res[2]) ) 
    {
      spad_log(message:'Jenkins found in redirect\n');
      installed = TRUE;
    }
  }

  spad_log(message:'Jenkins_ver: ' + jenkins_ver + '\n');

  # parse version from result body
  if (empty_or_null(jenkins_ver))
  {
    # Check for open source Jenkins
    item = pregmatch(pattern: "Jenkins ver.\s*([0-9.]+)(-SNAPSHOT)?\s*<", string: res[2]);
    if (!isnull(item))
    {
      spad_log(message:'Open Source Jenkins\n');
      jenkins_ver = item[1];
    }

    # Check for enterprise Jenkins
    item = pregmatch(pattern: "Jenkins ver.\s*([0-9.]+)(-SNAPSHOT)?\s*\(Jenkins Enterprise by CloudBees ([0-9.]+)\)<", string: res[2]);
    if (!empty_or_null(item))
    {
      spad_log(message:'Jenkins Enterprise\n');
      jenkins_ver = item[1];
      cloudbees_ver = item[2];
    }
  }

  var product, extra;
  
  if (installed)
  {
    spad_log(message:'Jenkins installed\n');

    replace_kb_item(name:'www/Jenkins', value:TRUE);
    set_kb_item(name:"www/Jenkins/"+port+"/Installed", value:TRUE);

    if (!empty_or_null(cloudbees_ver))
    {
      spad_log(message:'Cloudbees version found\n');
      set_kb_item(name:"www/Jenkins/"+port+"/enterprise/Installed", value:TRUE);
      set_kb_item(name:"www/Jenkins/"+port+"/enterprise/CloudBeesVersion", value:cloudbees_ver);
      product = "Jenkins Enterprise by CloudBees";
      edition = "Enterprise";
    }
    else
    {
      # If no version, just call it Open Source
      if (empty_or_null(jenkins_ver))
      {
        spad_log(message:'Open Source version found\n');
        jenkins_ver = 'unknown';
        product = "Jenkins Open Source";
        edition = "Open Source";
      }
      else
      {
        spad_log(message:'Not Cloudbees, not Open Source\n');
        # All LTS releases are max_index >= 3
        # All non-LTS releases are max_index == 2, EXCEPT one non-LTS
        # release : 1.395.1, so do not mark that one as LTS
        if (
          (max_index(split(jenkins_ver, sep:".", keep:FALSE)) >= 3) &&
          jenkins_ver != '1.395.1'
        )
        {
          spad_log(message:'Jenkins Open Source LTS\n');
          product = "Jenkins Open Source LTS";
          is_LTS = TRUE;
          set_kb_item(name:"www/Jenkins/" + port + "/is_LTS", value:TRUE);
          edition = "Open Source LTS";
        }
        else
        {
          spad_log(message:'Jenkins Open Source\n');
          product = "Jenkins Open Source";
          edition = "Open Source";
        }
      }
    }

    if (empty_or_null(hudson_ver)) hudson_ver = 'unknown';

    set_kb_item(name:"www/Jenkins/" + port + "/JenkinsVersion", value:jenkins_ver);
    set_kb_item(name:"www/Jenkins/" + port + "/HudsonVersion", value:hudson_ver);

    extra = make_array("Edition", edition, "Hudson Version", hudson_ver, "LTS", is_LTS);
    if (!empty_or_null(cloudbees_ver))
      extra["CloudBees Version"] = cloudbees_ver;

    # register the install
    installs++;
    register_install(
      app_name : appname,
      vendor : 'CloudBees',
      product : 'Jenkins',
      path     : dir,
      version  : jenkins_ver,
      port     : port,
      cpe      : "cpe:/a:cloudbees:jenkins",
      webapp   : TRUE,
      extra    : extra
    );

    if (thorough_tests)
      continue;
    else
      break;

  }
}

if (installs == 0)
  audit(AUDIT_WEB_APP_NOT_INST, appname, port);

# Report findings.
report_installs(port:port, app_name:appname);

