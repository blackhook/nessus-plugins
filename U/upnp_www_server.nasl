#TRUSTED 6865b7f97c30379527d4fb60c80af43074eebce04b83789fa3c3a485741af476b2ee1f8101031e3faddf01fd7818e097f1351942e5749f8e3b0517c2078b121ba78c6e26b52de312dd12be9641c44493116138deea12f319c4ec0c71fd353177069aca6a7c5286e8a2622b5738556bb79220039e55df68f686fe3184d82c1410ca5c9e77bdf95d9f0856910a4a9dcb5e83db16ae109406344aea7fdcc20ad14c2c831006159d3a1b1c70cbe82845c1a77efb8a078e695156939ca312aeae0d675751df09ea52aec9ec5ec50f8a0769146797e83d5e8179c80f8c9eef8a16a8c160e8888f58a5fcc1744b50aeca667c56650f6a10619803d50f4211dfb142eae1a5fdc78e1897f9953225bdbcb7fa8a826cfdf9424841f89740cc9b2468d185766d94767685eb59599ea723e683a28dbfba518a8a800f36f5fec52156b6e5e7e24bee50cc33463829b1567fd209739aef32f8245331d0b7cfcc88b57ad68bef3d0c9046c111bda09cfd553f8d963bb889da06efa4ef225461083f9b3820f3e817398f96b5667d9eef1b1d8e4edc46bb799ab2d33dfc404c0e0b76cb872739b52fa8cf3d11245d46f8c60cf3a5766d924854b69d88083d25bfa45f7a24a6a22edc69556379c0cd23c817cf152b0a0d5a81a6d22b790d453f71d460d889572e77ea52f7b7206debb004dbd530a6dc3906fdb15def8336bc0eacf9d7051886ef0c07

#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
 script_id(35712);
 script_version("1.22");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

 script_name(english:"Web Server UPnP Detection");
 script_summary(english:"Grabs the UPnP XML description file.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server provides UPnP information.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to extract some information about the UPnP-enabled
device by querying this web server. Services may also be reachable
through SOAP requests.");
 script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Universal_Plug_and_Play");
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port if desired.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/19");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");

 script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("http_version.nasl", "upnp_search.nasl");
 script_require_keys("upnp/location");

 exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include("xml_func.inc");
include('audit.inc');
include("install_func.inc");
include('spad_log_func.inc');

##
# Queries the remote host for the provided item and
# verifies that it appears to serve XML.
# @param port the port to query
# @param item the page to request from the server
# @return the XML page or null
##
function get_devdescr(port, item)
{
  if (empty_or_null(item)) return NULL;
  # Disable the keepalive; the Windows Network Sharing UPNP server doesn't like the keepalive
  http_disable_keep_alive();
  local_var r = http_send_recv3(method:"GET",
                                port:port,
                                item:item,
                                host:get_host_ip(), # this must be an IP address
                                exit_on_fail:FALSE);

  if (!isnull(r) && '200 OK' >< r[0] && '<?xml version="1.0"' >< r[2])
  {
    set_kb_item(name:'upnp/' + url_split["port"] + '/www/banner', value:r[1]);
    return r[2];
  }
  return NULL;
}

##
# Stores an XML value into the KB. By default the value will be
# stored in 'upnp/port/name', but if 'key' is provided the value
# will be stored at 'upnp/port/key/name'
#
# @param xml an xml tree to extract the value from
# @param name the name of the value in the xml tree
# @param port the port we are operatin on
# @param key [optional] an extended KB name
# @ret a textual representation of the stored data
##
function store_xml_item(xml, name, port, key, count)
{
    local_var rep = "";
    local_var result = xml_get_child(table:xml, name:name);
    if (!isnull(result))
    {
      if (isnull(key))
      {
        if (!isnull(result['value']))
          set_kb_item(name:'upnp/'+ port + '/' + count + '/' + name, value: result['value']);
      }
      else
      {
        if (!isnull(result['value']))
          set_kb_item(name:'upnp/'+ port + '/' + count + '/' + key + '/' + name, value: result['value']);
      }

      rep = (name + ": " + result["value"] + '\n');
    }
    return rep;
}

##
# Parses the service list in order to collect the URLs needed for
# API, control, and event gathering.
#
# @param device the device XML
# @param port the port we are operating on
# @return rep a string representation of what was found
##
function do_service_list(device, port, count)
{
  local_var rep = "";
  local_var service_list = xml_get_child(table:device, name:'serviceList');
  if (isnull(service_list)) return rep;

  local_var services = xml_get_children(table:service_list, name:"service");
  if (isnull(services)) return rep;

  local_var service;
  foreach(service in services)
  {
    local_var serviceId = xml_get_child(table:service, name:'serviceId');
    if (isnull(serviceId) || len(serviceId['value']) == 0) continue;
    set_kb_item(name:'upnp/'+ port + '/' + count + '/service', value:serviceId['value']);

    local_var key = 'service/' + serviceId['value'];
    rep += ('ServiceID: ' + serviceId['value'] + '\n');
    rep += '\t';
    rep += store_xml_item(xml:service, name:'serviceType', port:port, key:key, count:count);
    rep += '\t';
    rep += store_xml_item(xml:service, name:'controlURL', port:port, key:key, count:count);
    rep += '\t';
    rep += store_xml_item(xml:service, name:'eventSubURL', port:port, key:key, count:count);
    rep += '\t';
    rep += store_xml_item(xml:service, name:'SCPDURL', port:port, key:key, count:count);
  }

  return rep;
}

##
# Looks through the provided xml for the top level device fields (which will
# be displayed in the report). Also, locates the service fields.
#
# @param xml - the xml data
# @param port - the port we are scanning
# @return rep - the extracted fields in a format usable with 'security_report'
##
function parse_devdescr(xml, port, count)
{
  if (isnull(xml)) return NULL;

  if ('encoding="gbk"' >< xml)
  {
    ##
    #  'gbk' encoding not supported by xmlparse().
    #  replace with 'utf-8'
    ##
    spad_log(message:'xml modified from\n' + obj_rep(xml) + '\n');
    xml = str_replace(string:xml, find:'encoding="gbk"', replace:'encoding="utf-8"');
    spad_log(message:'to\n' + obj_rep(xml) + '\n');
  }

  local_var rep = NULL;
  local_var rootxml = xmlparse(xml);
  local_var device = xml_get_child(table:rootxml, name:'device');
  if (isnull(device)) return NULL;

  # This stores the top level device information. There could be
  # other child device trees but we don't need to parse those
  rep = store_xml_item(xml:device, name:'deviceType', port:port, count:count);
  rep += store_xml_item(xml:device, name:'friendlyName', port:port, count:count);
  rep += store_xml_item(xml:device, name:'manufacturer', port:port, count:count);
  rep += store_xml_item(xml:device, name:'manufacturerURL', port:port, count:count);
  rep += store_xml_item(xml:device, name:'modelName', port:port, count:count);
  rep += store_xml_item(xml:device, name:'modelDescription', port:port, count:count);
  rep += store_xml_item(xml:device, name:'modelName', port:port, count:count);
  rep += store_xml_item(xml:device, name:'modelNumber', port:port, count:count);
  rep += store_xml_item(xml:device, name:'modelURL', port:port, count:count);
  rep += store_xml_item(xml:device, name:'serialNumber', port:port, count:count);

  rep += do_service_list(device:device, port:port, count:count);

  # Oddly, there can be an ever descending tree of deviceLists. And if
  # you are reading this true loop, I'm sure you have concerns. Good.
  # However, the loop always descends down further into the tree due
  # to the reuse of 'device' in the first xml_get_child and in the
  # return value of the second xml_get_child.
  while(TRUE)
  {
    local_var deviceList = xml_get_child(table:device, name:'deviceList');
    if (isnull(deviceList)) return rep;

    device = xml_get_child(table:deviceList, name:'device');
    if (isnull(device)) return rep;

    store_xml_item(xml:device, name:'deviceType', port:port, count:count);
    rep += do_service_list(device:device, port:port, count:count);
  }

  return rep;
}

# Loop over the locations and try to read their xml descriptions
vuln = FALSE;
locations = get_kb_list('upnp/location');

# there may be more than a single upnp service per port
# so we will number them, starting with 1
var loc_count = 0;

foreach(location in locations)
{
  loc_count += 1;

  url_split = split_url(url:location);
  if (isnull(url_split)) continue;

  # only continue if we are certain this points at our target
  if (get_host_ip() != url_split["host"]) continue;

  gd = get_devdescr(port:url_split["port"], item:url_split["page"]);
  if (isnull(gd)) continue;

  set_kb_item(name:'upnp/www', value:url_split["port"]);

  # this will indicate how many separate upnp services are running on this port
  replace_kb_item(name:'upnp/' + url_split["port"] + '/num_services', value:loc_count);
  
  set_kb_item(name:'upnp/' + url_split["port"] + '/' + loc_count + '/location', value:location);
  if (service_is_unknown(port:url_split["port"])) register_service(port:url_split["port"], proto:'www');

  parsed = parse_devdescr(xml:gd, port:url_split["port"], count:loc_count);
  if (isnull(parsed) || len(parsed) == 0) continue;

  report = NULL;
  vuln = TRUE;
  if (strlen(parsed)) report = '\nHere is a summary of ' + location + ' :\n\n' + parsed;
  else report = '\nBrowse ' + location + ' for more information\n';
  security_report_v4(port:url_split["port"],
                     severity:SECURITY_NOTE,
                     extra:report);
}

if (vuln == FALSE) audit(AUDIT_HOST_NOT, 'affected');
