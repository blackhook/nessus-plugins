#
# (C) Tenable Network Security, Inc.
#

# Thanks to Jason Haar for his help!


include('compat.inc');

if (description)
{
  script_id(51185);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_xref(name:"IAVT", value:"0001-T-0580");

  script_name(english:"Dell Integrated Remote Access Controller (iDRAC) Detection");
  script_summary(english:"Detects the iDRAC web server.");

  script_set_attribute(attribute:"synopsis", value:
"A remote management service is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote web server has been fingerprinted as one embedded in Dell
Integrated Remote Access Controller (iDRAC), formerly known as Dell
Remote Access Controller (DRAC).");
  # http://www.dell.com/learn/us/en/555/solutions/integrated-dell-remote-access-controller-idrac
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da64eb28");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:remote_access_card");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac6");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac7");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac8");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac9");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"hardware_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "httpver.nasl", "broken_web_server.nasl");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('http.inc');
include('install_func.inc');
include('debug.inc');

# iDRAC is fragile, we do not want to miss it.
http_set_read_timeout(get_read_timeout() * 2);

http_set_gzip_enabled(TRUE);

var port = get_http_port(default: 443, embedded: TRUE);

# page_1 for debugging
var page = http_send_recv3(
  port   : port,
  method :'GET',
  item   : "/",
  follow_redirect : 2,
  exit_on_fail    : TRUE);

dbg::detailed_log(
  lvl:3, 
  src:'http_send_recv3() line 67.' , 
  msg:'Response Code: '  + page[0] +
      'Headers:\n'       + page[1] +
      'Response Body:\n' + page[2]
);

var drac_detected = FALSE;
var fw_ver = UNKNOWN_VER;
var drac_version = UNKNOWN_VER;
var link, match;

# In some cases, Versions 5, 6, and 7 use a JavaScript redirect
# we will manually look for and handle the redirect
if (
  "function redirect()" >< page[2] ||
  '"javascript:redirect();"' >< page[2]
)
{
  dbg::detailed_log(lvl:1, msg:"Potential fingerprints for iDRAC 5/6/7");
  link = NULL;
  # iDRAC 6/7 examples:
  # top.document.location.href= "/login.html";
  # top.document.location.href = "/index.html";
  match = egrep(
    pattern : 'top\\.document\\.location\\.href(\\s)?= "/(index|login)\\.html"',
    string  : page[2]
  );
  if (match) link = "/login.html";
  else if (!match)
  {
    match = pregmatch(
      pattern : 'top\\.document\\.location\\.replace\\("(.*)"\\)',
      string  : page[2]
    );
    if (!empty_or_null(match)) link = match[1];
  }

  if (link)
  {
    # page_2 for debugging
    page = http_send_recv3(
     method : "GET",
     port   : port,
     item   : link,
     exit_on_fail : TRUE
    );

    dbg::detailed_log(
      lvl:3, 
      src:'http_send_recv3() page_2' , 
      msg:'Response Code: '  + page[0] +
          'Headers:\n'       + page[1] +
          'Response Body:\n' + page[2]
    );
  }
}

# Check if it looks like DRAC 4
var ver, res, build;

if ("<title>Remote Access Controller</title>" >< page[2])
{
  dbg::detailed_log(lvl:1, msg:'Potential fingerprints for iDRAC 4');
  drac_detected = TRUE;
  ver = pregmatch(
    pattern : 'var s_oemProductName = "DRAC ([0-9]+)"',
    string  : page[2]
  );
  if (!empty_or_null(ver)) drac_version = ver[1];
  else drac_version = "4 or earlier";

  # Grab version from /cgi/about page
  res = http_send_recv3(
    method  : "GET",
    item    : "/cgi/about",
    port    : port,
    exit_on_fail : TRUE
  );
  build = pregmatch(
    pattern : 'var s_build = "([0-9\\.]+) \\(Build .*',
    string  : res[2]
  );
  if (!empty_or_null(build)) fw_ver = build[1];
}

# DRAC 5
# Check for response expected to be seen on /cgi-bin/webcgi/index
var res2;
if (
  egrep(pattern:'\\<IpAddress\\>([0-9\\.]+)\\</IpAddress\\>', string:page[2], icase:TRUE) &&
  ("<drac>" >< page[2]) && ("</drac>" >< page[2])
)
{
  dbg::detailed_log(lvl:1, msg:'Potential fingerprints for iDRAC 5');
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : "/cgi/lang/en/login.xsl",
    exit_on_fail : TRUE
  );
  if ("Dell Remote Access Controller" >< res[2])
  {
    drac_detected = TRUE;

    ver = pregmatch(
      pattern : 'strProductName"\\>DRAC ([0-9]+)\\<',
      string  : res[2]
    );
    if (!empty_or_null(ver)) drac_version = ver[1];
    else drac_version = "5 or earlier";

    # Get DRAC version from /cgi-bin/webcgi/about
    res2 = http_send_recv3(
      method : "GET",
      port   : port,
      item   : "/cgi-bin/webcgi/about",
      exit_on_fail : TRUE
    );

    if ("<drac>" >< res2[2])
    {
      build = pregmatch(
        pattern :"<FirmwareVersion>([0-9\.]+)</FirmwareVersion>",
        string  : res2[2]
      );
      if (!empty_or_null(build)) fw_ver = build[1];
    }
  }
}

# DRAC 6 / 7
var pat = "<title>(Integrated)?((\s)?Dell)? Remote Access Controller [0-9]+";
if (
  egrep(pattern:pat, string:page[2], icase:TRUE) ||
  page[2] =~ 'eLang.getString\\("STR_DEFAULT_DOMAIN"\\)\\s*\\+\\s*"iDRAC[67]"'
)
{
  dbg::detailed_log(lvl:1, msg:'Potential fingerprints for iDRAC 6/7');
  drac_detected = TRUE;
  # grab the version from /public/about.html
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : "/public/about.html",
    exit_on_fail : TRUE
  );

  if(!res[2] || "Remote Access Controller" >!< res[2])
  {
    res = http_send_recv3(
      method : "GET",
      port   : port,
      item   : "/Applications/dellUI/Strings/EN_about_hlp.htm",
      exit_on_fail : TRUE
    );
  }

  if (res[2] =~ "Remote Access Controller [0-9]+")
  {
    ver = pregmatch(pattern:"Remote Access Controller ([0-9]+)",string:res[2]);
    if (!empty_or_null(ver)) drac_version = ver[1];
    else drac_version = "6, 7 or later";

    ver = pregmatch(
      pattern : 'var fwVer = "([0-9.]+)(\\(Build [0-9]+\\))?"',
      string  : res[2]
    );

    if (empty_or_null(ver))
      ver = pregmatch(pattern:"Version\s*([0-9.]+)[\s\n]*<", string:res[2]);

    if (!empty_or_null(ver)) fw_ver = ver[1];
    if (!empty_or_null(ver[2])) fw_ver = ver[1] + "." + ver[2];

  }
}

# DRAC 8 and newer versions require ajax to display version info on about page
var drac_gen;
if("/session?aimGetProp=fwVersionFull" >< page[2] ||
   page[2] =~ "gen_iDrac[\d+]")
{
  dbg::detailed_log(lvl:1, msg:'Potential fingerprints for iDRAC 8');
  drac_detected = TRUE;

  # there may be some fingerprint overlap between 7 and 8
  # to solve that, we try retrieve the prodServerGen
  # 12G is iDRAC 7, 13G is iDRAC 8
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : "/data?get=prodServerGen",
    exit_on_fail : FALSE
  );

  if (!empty_or_null(res[2]))
  {
    drac_gen = pregmatch(string:res[2], pattern:'<prodServerGen>(\\d+G)</prodServerGen>');
    if (!isnull(drac_gen))
    {
      dbg::detailed_log(lvl:1, msg:'iDRAC Generation: ' + drac_gen[1]);
      if (drac_gen[1] == "12G")
        drac_version =  "7";
      else if (drac_gen[1] == "13G")
        drac_version = "8";
    }
  }

  if (drac_version == UNKNOWN_VER)
  {
    # multiple versions may be present on a page
    # we need to parse the page for the highest
    # DRAC version
    if ("gen_iDrac6" >< page[2]) ver = "6";
    if ("gen_iDrac7" >< page[2]) ver = "7";
    if ("gen_iDrac8" >< page[2]) ver = "8";
    if (!empty_or_null(ver)) drac_version = ver;
  }

  # request/parse firmware version
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : "/session?aimGetProp=fwVersionFull",
    exit_on_fail : TRUE
  );

  # parse the build version and append to Firmware Version
  #
  # DRAC 8 Example:
  #   fwVersionFull" :"2.30.30.30 (Build 50)
  ver = pregmatch(pattern:'fwVersionFull.+?([0-9.]+)(\\s*\\(Build\\s([0-9]+))?',
                  string:res[2]);

  if (!empty_or_null(ver)) fw_ver = ver[1];
  if (!empty_or_null(ver)) fw_build = ver[3];
  if ((!empty_or_null(fw_ver)) && (!empty_or_null(fw_build)))
    fw_ver = fw_ver + "." + fw_build;
}

# DRAC 9
var match_ver, match_fw, match_build, fw_build;
if ("idrac-start-screen" >< page[2])
{
  # request restgui/locale/strings/locale_str_en.json
  dbg::detailed_log(lvl:1, msg:'Potential fingerprints for iDRAC 9');
  
  # res_idrac_ver for debugging
  res = http_send_recv3(
    method:"GET",
    port:port,
    item:"/restgui/locale/strings/locale_str_en.json",
    exit_on_fail: TRUE
  );

  dbg::detailed_log(
    lvl:3, 
    src:'http_send_recv3(): res_idrac_ver' , 
    msg:'Response Code: '  + res[0] +
        'Headers:\n'       + res[1] +
        'Response Body:\n' + res[2]
  );

  match_ver = pregmatch(string:res[2], pattern:'"app_title":\\s*"iDRAC(\\d+)"');
  if (!isnull(match_ver))
  {
    drac_version = match_ver[1];
    drac_detected = TRUE;
  }

  # sysmgmt/2015/bmc/info for the FW and build info
  # res_firmware_ver for debugging
  res = http_send_recv3(
    method:"GET",
    port:port,
    item:"/sysmgmt/2015/bmc/info",
    exit_on_fail: FALSE
  );

  if (!empty_or_null(res) && !empty_or_null(res[2]))
  {
    dbg::detailed_log(
      lvl:3, 
      src:'http_send_recv3() res_firmware_ver.' , 
      msg:'Response Code: '  + res[0] +
          'Headers:\n'       + res[1] +
          'Response Body:\n' + res[2]
    );

    match_fw = pregmatch(string:res[2], pattern:'"FwVer"\\s*:\\s*"([\\d.]+)"');
    if (!isnull(match_fw))
    {
      fw_ver = match_fw[1];
    }

    match_build = pregmatch(string:res[2], pattern:'"BuildVersion"\\s*:\\s*"(\\d+)"');
    if (!isnull(match_build))
    {
      fw_build = match_build[1];
    }

    if (!empty_or_null(fw_ver) && !empty_or_null(fw_build))
    {
      fw_ver = fw_ver + '.' + fw_build;
    }
  }
}

# DRAC/MC (Dell Remote Access Controller/Modular Chassis)
pat = "Dell\(TM\) Remote Access Controller/Modular Chassis\</title\>";
if (egrep(pattern:pat, string:page[2], icase:TRUE))
{
  dbg::detailed_log(lvl:1, msg:'Potential fingerprints for DRAC/MC');
  drac_detected = TRUE;

  # Grab Version from /about.html
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : "/about.htm",
    exit_on_fail : TRUE
  );

  if (egrep(pattern:pat, string:res[2], icase:TRUE))
  {
    drac_version = "DRAC/MC";
    ver = pregmatch(
      pattern : "Version .* &nbsp;([0-9\.]+) \(Build .*\)\<",
      string  : res[2]
    );
    if (!empty_or_null(ver)) fw_ver = ver[1];
  }
}

# DRAC is detected on 443, but NAT or RP may be in place
var disabled_port, cache;
if (port != 80)
{
  # Play on the safe side: disable port 80 too.
  disabled_port = 80;
  cache = http_get_cache(port: disabled_port, item: '/');
  if ( 'HTTP/1.1 301 ' >< cache &&
       egrep(string: cache, pattern: '^Location: *https://.*/start.html') )
  {
    declare_broken_web_server(port:disabled_port, reason:'iDRAC web interface is fragile.');
  }
}

if (drac_detected)
{
  set_kb_item(name: 'Services/www/' + port + '/embedded', value: TRUE);

  register_install(
    vendor   : "Dell",
    product  : "Remote Access Card",
    port     : port,
    app_name : 'iDRAC',
    path     : "/",
    version  : drac_version,
    extra    : make_array('Firmware Version', fw_ver),
    webapp   : TRUE,
    cpe   : "cpe:/h:dell:remote_access_card");

  report_installs(app_name:'iDRAC', port:port);
}
else audit(AUDIT_WEB_APP_NOT_INST, 'iDRAC', port);
