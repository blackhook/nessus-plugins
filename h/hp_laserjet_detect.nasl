#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36128);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/09");

  script_xref(name:"IAVT", value:"0001-T-0611");

  script_name(english:"HP LaserJet Printer Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is a printer.");
  script_set_attribute(attribute:"description", value:
"The remote host is an HP LaserJet printer.");
  script_set_attribute(attribute:"see_also", value:"https://www.hp.com/us-en/printers/laserjet-printers.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:laserjet");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"hardware_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("httpver.nasl");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("http.inc");

var port = get_http_port(default:443, dont_break: 1,embedded:1);

var banner = get_http_banner(port:port);

var lb = '';
if (banner) lb = tolower(banner);

if (
  !lb ||
  (
    "server: $projectrevision" >!< lb &&
    "server: hp-chaisoe" >!< lb &&
    "server: hp-chaiserver" >!< lb &&
    "server: virata-emweb" >!< lb &&
    "server: hp_compact_server" >!< lb
  )
) audit(AUDIT_WRONG_WEB_SERVER, port, "a HP LaserJet");

var kb_base = "www/hp_laserjet";
var kb_include_port = FALSE;

var labels = {};
labels["pname"] = "Product Name";
labels["fw"] = "Firmware";
labels["serial"] = "Serial Number";
labels["fw_rev"] = "Firmware Revision";
labels["fw_bundle_ver"] = "Firmware Bundle Version";
labels["modelnumber"] = "Model Number";
labels["url"] = "URL";

#Firmware Number labels

var firmware_vals = make_list(
  "Firmware",
  "firmware",
  "Date/code microgl"
);

#Serial Number labels
var serial_vals = make_list(
  "Serial Number",
  "Numero di serie stampante",
  "Produkt-Seriennummer",
  "Numero di serie del produtto",
  "Serienummer for produkt",
  "Produktens serienummer"
);

#Collect various pieces of data.
var data = make_array();

# Newer models
var item = "/hp/device/InternalPages/Index?id=ConfigurationPage";
var res = http_send_recv3(method:"GET", port:port, exit_on_fail:TRUE, item:item);

var pname_pat =
'"product">(?:[\\n\\s]+)?(?:HP|hp) (?:Color )?LaserJet (?:[0-9]+ )?(?:Flow|MFP)* *([A-Za-z0-9]+)';

var matches = NULL;

if (res[2] =~ '<title>([\\n\\s]+)?HP .*Configuration Page</title>' &&
    res[2] =~ pname_pat)
{
  matches = pregmatch(pattern:pname_pat, string:res[2]);
  if (!empty_or_null(matches)) data["pname"] = matches[1];

  matches = pregmatch(pattern:'id="FirmwareDatecode">([0-9]+)</', string:res[2],icase:TRUE);
  if (!empty_or_null(matches)) data["fw"] = matches[1];

  matches = pregmatch(pattern:'id="FirmwareRevision">([^<]+)</', string:res[2], icase:TRUE);
  if (!empty_or_null(matches)) data["fw_rev"] = matches[1];

  matches = pregmatch(pattern:'id="FutureSmartBundleVersion">([^<]+)</', string:res[2], icase:TRUE);
  if (!empty_or_null(matches)) data["fw_bundle_ver"] = matches[1];

  matches = pregmatch(pattern:'id="ModelNumber">([^<]+)</', string:res[2], icase:TRUE);
  if (empty_or_null(matches))
    data["modelnumber"] = "unknown";
  else
    data["modelnumber"] = matches[1];

  matches = pregmatch(pattern:'id="SerialNumber">([^<]+)</', string:res[2], icase:TRUE);
  if (empty_or_null(matches))
    data["serial"] = "unknown";
  else
    data["serial"] = matches[1];

  data["url"] = build_url(port:port, qs:item);

  kb_include_port = TRUE;
  
}

var line;

# Older models
if (empty_or_null(data["pname"]) || empty_or_null(data["fw"]))
{
  res = http_send_recv3(method:"GET", port:port, exit_on_fail: TRUE,
      item:"/hp/device/this.LCDispatcher?nav=hp.config");

  # - Grab the product model
  if (res[2] =~ '<title>([\\n\\s]+)?(HP|hp) (Color )?LaserJet ([A-Za-z0-9]+)')
  {
    info = strstr(res[2], "<title>");
    if ("</title>" >< info)
    {
      info = chomp(info - strstr(info, "</title>"));
      pat = '(<title>)?(HP|hp) (Color )?LaserJet ([A-Za-z0-9]+)';
      foreach line (split(info, keep:FALSE))
      {
        if (preg(pattern:pat, string:line))
        {
          matches = pregmatch(pattern:pat, string:line);
          if (!empty_or_null(matches))
            data["pname"] = matches[4];
          break;
        }
      }
    }
  }
  # - Grab the firmware version
  foreach val (firmware_vals)
  {
    if (val >< res[2])
    {
      info = strstr(res[2], val);
      if (preg(string:info, pattern:strcat(val, "([\\w\\s]+):</div")))
      {
        info = info - strstr(info, "hpDataItem");
        pat = '([\\d]{8}([\\s]+[\\d]+.[\\d]+.[\\d]+)?)';
        foreach line (split(info, keep:FALSE))
        {
          if (preg(pattern:pat, string:line))
          {
            data["fw"] = preg_replace(pattern:pat, replace:"\1", string:line);
            break;
          }
        }
      }
      else
      {
        info = info - strstr(info, "</tr");
        pat  = '[\\d]{8}([\\s]+[\\d]+.[\\d]+.[\\d]+)?';
        foreach line (split(info, keep:FALSE))
        {
          if (preg(pattern:pat, string:line))
          {
            matches = pregmatch(pattern:pat, string:line);
            if (!empty_or_null(matches))
              data["fw"] = matches[0];
            break;
          }
        }
      }
    }
  }

  # - Grab the Serial Number
  foreach val (serial_vals)
  {
    if (val >< res[2])
    {
      info = strstr(res[2], val);
      if (preg(string:info, pattern:strcat(val, "[\\w\\s]+:</div")))
      {
        info = info - strstr(info, "hpDataItem");
        pat = '"hpDataItemValue">(\\s+)([\\w\\d]{10})</div>';
        foreach line (split(info, keep:FALSE))
        {
          if (preg(pattern:pat, string:line))
          {
            matches = pregmatch(pattern:pat, string:line);
            if (!empty_or_null(matches))
              data["serial"] = matches[2];
            break;
          }
        }
      }
      else
      {
        info = info - strstr(info, "</tr");
        if (preg(string:info, pattern:strcat(val, ":<")))
          pat = '>([\\w\\d]{10})<';
        else
          pat = val + ':[\\s]+([\\w\\d]{10})';

        foreach line (split(info, keep:FALSE))
        {
          if (preg(pattern:pat, string:line))
          {
            matches = pregmatch(pattern:pat, string:line);
            if (!empty_or_null(matches))
              data["serial"] = matches[1];
            break;
          }
        }
      }
    }
  }
}

# - Check for the Virata-EmWeb server if nothing was found.
if(
  !(data["pname"] ||
    data["fw"] ||
    data["serial"]
  )
)
{
  res = http_send_recv3(method:"GET", port:port, item:"/SSI/info_configuration.htm", exit_on_fail:TRUE);
  if ("LaserJet" >!< res[2]) res = http_send_recv3(method:"GET", port:port, item:"/info_configuration.html", exit_on_fail:TRUE);
    # - Grab the product model
    if (res[2] =~ '<title>([\\n\\s]+)?(HP|hp) (Color )?LaserJet ((Professional )?[A-Za-z0-9]+)')
    {
      info = strstr(res[2], "<title>");
      if ("</title>" >< info)
      {
        info = info - strstr(info, "</title>");
        pat = '(HP|hp) (Color )?LaserJet ((Professional )?[A-Za-z0-9]+)';
        foreach line (split(info, keep:FALSE))
        {
          if (preg(pattern:pat, string:line))
          {
            matches = pregmatch(pattern:pat, string:line);
            if (!empty_or_null(matches))
              data["pname"] = matches[3];
            break;
          }
        }
      }
    }
    # - Grab the firmware version
    foreach val (firmware_vals)
    {
      if (val >< res[2])
      {
        info = strstr(res[2], val);
        info = info - strstr(info, "</tr");
        pat = '>([\\d]{8}([\\s]+[\\d]+.[\\d]+.[\\d]+)?)<';
        foreach line (split(chomp(info), keep:FALSE))
        {
          if (preg(pattern:pat, string:line))
          {
            matches = pregmatch(pattern:pat, string:line);
            if (!empty_or_null(matches))
              data["fw"] = matches[1];
            break;
          }
        }
      }
    }
    # - Grab the Serial Number
    foreach val (serial_vals)
    {
      if (val >< res[2])
      {
        info = strstr(res[2], val);
        info = info - strstr(info, "</tr");
        pat = '"itemFont">([\\w\\d]{10})<';
        foreach line (split(info, keep:FALSE))
        {
          if (preg(pattern:pat, string:line))
          {
            matches = pregmatch(pattern:pat, string:line);
            if (!empty_or_null(matches))
              data["serial"] = matches[1];
            break;
          }
        }
      }
    }

  if(
    !(data["pname"] ||
      data["fw"] ||
      data["serial"]
    )
  ) audit(AUDIT_UNKNOWN_DEVICE_VER, "HP LaserJet");
}

# Update KB and report findings.
set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
set_kb_item(name:kb_base, value:TRUE);

var max_label_len = 0;
var key, val;

foreach key (keys(data))
{
  label = labels[key];
  if (strlen(label) > max_label_len) max_label_len = strlen(label);
}

info = NULL;

foreach key (keys(data))
{
  val = data[key];
  if (empty_or_null(val)) continue;

  if (kb_include_port)
    set_kb_item(name:kb_base+"/" + port + "/" + key, value:val);
  else
    set_kb_item(name:kb_base+"/"+key, value:val);

  label = labels[key];
  if (key == "pname") val = 'HP LaserJet ' + val;
  info += '  ' + label + crap(data:" ", length:max_label_len-strlen(label)) + ' : ' + val + '\n';
}

set_kb_item(name:kb_base+"/port", value:port);

var report = '\n' + info;

security_report_v4(severity:SECURITY_NOTE, extra:report, port:port);

