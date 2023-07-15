#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93741);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_xref(name:"IAVT", value:"0001-T-0760");

  script_name(english:"Apple TV Version Detection");
  script_summary(english:"AppleTV version detection.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to obtain the version and model of the remote Apple TV
device.");
  script_set_attribute(attribute:"description", value:
"The remote host is an Apple TV device. Nessus was able to obtain its
version and model information via an HTTP request for the
'/server-info' resource.

Note that if 'Show potential false alarms' is enabled, this plugin
may result in false positives.");
  script_set_attribute(attribute:"see_also", value:"https://www.apple.com/tv/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:tvos");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:apple:apple_tv");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"hardware_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("appletv_detect.nasl");
  script_require_ports(5000, 7000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("install_func.inc");
include("misc_func.inc");

# If we already have AppleTV information, exit
if (
  !isnull(get_kb_item('AppleTV/Port')) &&
  !isnull(get_kb_item('AppleTV/Model')) &&
  !isnull(get_kb_item('AppleTV/Version'))
) exit(0, "This device has already been detected as an Apple TV.");

product = "Apple TV";
cpe     = "cpe:/o:apple:tvos";

port = get_http_port(default:7000);

detected = appletv_version::detect::serverinfo();
if (!detected)
{
  detected = appletv_version::detect::airtunes_header();
}

if (!detected)
  audit(AUDIT_UNKNOWN_DEVICE_VER, product);

report_installs(app_name:product, port:port);


##
# Functions
##
namespace appletv_version
{
  var model, generation, confidence;
  var version = UNKNOWN_VER;

  namespace detect
  {
    ##
    # Retrieve version via the AirPlay /server-info response
    #
    # @return true if detected; false if not detected
    ##
    function serverinfo()
    {
      var installs, install, matches, generations, build_match;

      installs = get_installs(app_name:"Apple AirPlay", port:port);
      if (installs[0] != IF_OK) return false;

      # There should only be one
      foreach install (installs[1])
      {
        model = install["model"];
        if (empty_or_null(model))
          return false;

        matches = pregmatch(string:model, pattern:"^AppleTV([0-9]+,[0-9]+)$");
        if (empty_or_null(matches))
          return false;
       
        generations = {
          '1,1' : '1st',
          '2,1' : '2nd',
          '3,1' : '3rd',
          '3,2' : '3rd',
          '5,3' : '4th',
          '6,2' : '4K',
          '11,1': '4K 2nd Gen' # added 5/26/2021, based on reported version change. Unable to test at this time.
        };

        generation = generations[matches[1]];
 
        confidence = 91;
      
        build_match = install["osBuildVersion"];
        if (!empty_or_null(build_match))
          version = build_match;

        appletv_version::register(method:"AirPlay /server-info");

        return true;
      }

      return false;
    }

    ##
    # Retrieve version via the server header (e.g. Server: AirTunes/366.75.2)
    #
    # @remark This function requires paranoid reporting due to other AirPlay devices
    #         including Apple Homepod using the same type of header.
    #
    # @return true if detected; false if not detected; NULL otherwise
    ##
    function airtunes_header()
    {
      var server_header, air_version, first_digit, generations;

      if (report_paranoia < 2) return NULL;
      
      # try obtaining the server header with the AirTunes version (e.g. AirTunes/366.75.2)
      server_header = http_server_header(port:port);
      if (empty_or_null(server_header))
        return false;

      air_version = pregmatch(string:server_header, pattern:"AirTunes/([0-9.]+)");      
      if (empty_or_null(air_version))
        return false;

      # whole version string (e.g. 366.75.2)
      air_version = air_version[1];

      # retrieve the first digit, which should determine the AppleTV generation (e.g. 3)
      first_digit = air_version[0];

      generations = {
        '1' : '2nd',
        '2' : '3rd',
        '3' : '4th'
      };

      generation = generations[first_digit];
      if (isnull(generation))
        generation = '4K';

      confidence = 75;

      appletv_version::register(method:"AirTunes Header");

      return true;
    }
  }

  ##
  # Register KBs and via register_install()
  #
  # @param [method:string] method (usually function name) used for detection
  #
  # @return always true
  ##
  function register(method)
  {
    replace_kb_item(name:"AppleTV/Port", value:port);
    replace_kb_item(name:"AppleTV/URL", value:build_url(port:port, qs:'/'));

    # For AirTunes, we cannot determine the exact model and build 
    if (method != 'AirTunes Header')
    {
      replace_kb_item(name:"AppleTV/Version", value:version);
      replace_kb_item(name:"AppleTV/Model", value:model);
    }

    var os = product;
    if (!empty_or_null(generation))
      os += " (" + generation + " Generation)";

    # Use unseen 'model' (e.g. AppleTV7,1) as backup
    else if (!empty_or_null(model))
      os += " (" + model + ")";

    replace_kb_item(name:"Host/OS/AppleTV", value:os);
    replace_kb_item(name:"Host/OS/AppleTV/Confidence", value:confidence);
    replace_kb_item(name:"Host/OS/AppleTV/Type", value:"embedded");

    var extra = {};
    extra["Generation"] = generation;
    extra["Model"] = model;

    register_install(
      vendor   : "Apple",
      product  : "Apple TV",
      app_name : product,
      port     : port,
      path     : '/',
      version  : version,
      extra    : extra,
      cpe      : cpe,
      webapp   : TRUE
    );

    return true;
  }
}
