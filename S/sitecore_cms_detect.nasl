#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55978);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_name(english:"Sitecore CMS / Experience Platform (XP) Web Detection");

  script_set_attribute(attribute:"synopsis", value:
"The login page for Sitecore Content Management System (CMS) / Experience Platform (XP) 
was detected on the remote host.");
  script_set_attribute(attribute:"description", value:
"Sitecore CMS / Experience Platform (XP), a web-based content management system,  
was detected on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.sitecore.com");
  # https://doc.sitecore.com/xp/en/SdnArchive/Products/Sitecore%20V5/Sitecore%20CMS%207/ReleaseNotes/ChangeLog.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ce8f2d8");
  # https://dev.sitecore.net/Downloads/Sitecore_Experience_Platform.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d18188f2");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sitecore:cms");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("http.inc");
include("webapp_func.inc");
include("spad_log_func.inc");

if (get_kb_item("Settings/disable_cgi_scanning"))
  exit(0, "This plugin only runs if 'Scan web applications' is enabled.");

var app, cpe, port;
app = 'sitecore_cms';
cpe = 'cpe:/a:sitecore:cms';
port = get_http_port(default:80);

var version, major, minor, build, rev;
var installs, detected, extra;
installs = 0;

var dirs = make_list('/sitecore', cgi_dirs());
foreach var dir (dirs)
{
  version = UNKNOWN_VER;
  detected = FALSE;
  
  # Try login page first
  var item = dir + '/login/default.aspx';
  var web_res = http_send_recv3(method:'GET', item:item, port:port, exit_on_fail:TRUE);
  if (
       'Welcome to Sitecore'  >< web_res[2] &&
       'Sitecore.NET'         >< web_res[2]
    ) 
  {
    ##
    # Regex pattern for Sitecore should match the following
    # Sitecore.NET 10.2.0 (rev. 006766 Hotfix 1)
    # Sitecore.NET 10.2.0 (rev. 006766 Hotfix 1-2)
    # Sitecore.NET 10.2.0 (rev. 006766)
    ##
    var pattern = 'Sitecore.NET (\\d.+) \\(rev\\. (\\d+) ?(Hotfix \\d+|Hotfix \\d+-\\d+)?\\)';
    if (!empty_or_null(web_res)) var matches = pgrep(pattern:pattern, string:web_res[2]);
    else spad_log(message:'Sitecore responded with an empty or null value.');

    if (!empty_or_null(matches))
    {
      foreach var value (split(matches, keep:FALSE))
      {
        matches = pregmatch(pattern:pattern, string:value); 
        if (!isnull(matches))
        {
          # To prevent breakage of downstream plugins do not change format
          version = strcat(matches[1], ' rev. ', matches[2]);
          rev = matches[2];
          detected = TRUE;
        }
        else spad_log(message:"Failed to get a response from the web server.");

        if (!isnull(matches[3])) hotfix = matches[3];
        else spad_log(message:"The Hotfix information is not available.");
      }
    }
  }

  # Try sitecore.version.xml if initial detection fails
  if (version == UNKNOWN_VER || empty_or_null(version))
  {
    item = dir + '/shell/sitecore.version.xml';
    var xml_res = http_send_recv3(method:'GET', item:item, port:port, exit_on_fail:TRUE);
    if (
        'Sitecore Corporation'  >< xml_res[2] &&
        'Sitecore.NET'          >< xml_res[2]
      )
    {
      # Fixup the data and remove invalid characters inside xml
      var data = preg_replace(string:xml_res[2], pattern:"<company>(.*)</copyright>", replace:"");
      major = NULL; minor = NULL; build = NULL; rev = NULL;
      
      # Deserialize the xml data into an array data structure
      data = deserialize(options:SERIALIZE_XML, data);
      if (!isnull(data))
      {
        major = data['information']['version']['major'];
        minor = data['information']['version']['minor'];
        build = data['information']['version']['build'];
        rev = data['information']['version']['revision'];
        hotfix = data['information']['version']['hotfix'];
        detected = TRUE;
        
        # To prevent breakage of downstream plugins do not change format
        version = strcat(major, '.', minor, '.', build, ' rev. ', rev);
      }
      else spad_log(message:"Failed to deserialize the XML data in sitecore.version.xml");
    }
  }
  
  if (detected)
  {
    if (hotfix) extra['Hotfix'] = hotfix;
    if (rev) extra['Revision'] = rev;

    # Set so we don't break downstream plugins
    set_kb_item(name:"www/"+app, value:TRUE);

    register_install(
      app_name      : app,
      vendor : 'Sitecore',
      product : 'CMS',
      path          : dir,
      port          : port,
      version       : version,
      webapp        : TRUE,
      extra         : extra,
      cpe           : cpe
    );
    installs++;
    
    if (!thorough_tests) break;
  }
}

# If no installs were reported then exit with an audit trail
if (installs == 0) audit(AUDIT_WEB_APP_NOT_INST, app, port);

report_installs(app_name:app, port:port);
