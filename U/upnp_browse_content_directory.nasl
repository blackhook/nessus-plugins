#TRUSTED 3731504e7d18f8ac0b7eea7ada02e359c58c0b57810ee26a2bdcdd0328d17d5471d894163811a0d5e7b7606d2ae759d1059410b2d8b4e762268006b6b17f4caa2cd8d35b605be127e13f2e5a194e47bb42caf38a6f692dab447fd0d4b95ed5791eb775672e90f8f9a5204e88c2378ddb37d8a0ccb39da2af63bad1b2762b2f8b5e510c5f91270996747e05537c138d2e79755caa701a10b9ee7bf656ef8226788873ad13b822e3afe4837d48c5abac45fb1a451e0ab80ac0d84c3d111797dcb4f5175da3394832949b0285ab5fef61f920ba7d4351bbfbb0c5bcd595b8cfb40c7b1d9c7e3705aa7043886ddf8f9672f60d5aacfa649ee2eb40fa368a8427fd74ccd72e66f153ea25e83f894b59aff3af848193602d3d0b8a16c999e538c4d0465dbfede089c931a148b0956552b948dac29a3ee81facb2309bdc5d34477d89888ac191a552f1fc0c76c49916a00b1c39c7e669de3dd462fa6d6d3aba2e3689d4b90e5df08da80e0733265a139b62c64bfed760db1a01ec55f7d27b2842417573f91e99866544dfe9e8148fdaa3ea63d9af093ffa03647b3b32e68795d5d47aa50736faa3937002c396ce5f584db66ebe474415c4dc233416df5b36a1233e55ea6dda8efaee5fd9461f8af5e30c8370f2c2acdb5f6052d0aaf49cf1b13e968f02fd0d02ac2a5d37d00091006f65f719c5485c6cabfdfa0b6cdc941ba32b572be6

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(94046);
 script_version("1.6");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

 script_name(english: "UPnP File Share Detection");
 script_summary(english: "Lists the top level directories in the UPnP file share.");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is running a file server.");
 script_set_attribute(attribute:"description", value:
"According to its UPnP data, the remote device hosts a 'Content
Directory'. Therefore, an adjacent user can read shared files on the
host. This is often associated with a media server.");
 script_set_attribute(attribute:"see_also", value:"http://upnp.org/specs/av/UPnP-av-ContentDirectory-v1-Service.pdf");
 script_set_attribute(attribute:"solution", value:
"Ensure the file share is legitimate and in accordance with your
security policy.");
 script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/13");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "Misc.");

 script_copyright(english:"This script is Copyright (C) 2016-2020 Tenable Network Security, Inc.");

 script_dependencie("upnp_www_server.nasl");
 script_require_keys("upnp/www");

 exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include("xml_func.inc");
include('audit.inc');
include('http.inc');

port = get_kb_item_or_exit('upnp/www');
location = get_kb_item_or_exit('upnp/'+port+'/location');
services = get_kb_list('upnp/'+port+'/service');

report = '';
vuln = FALSE;
foreach(service in services)
{
  serviceType = list_uniq(get_kb_list('upnp/'+port+'/service/'+service+'/serviceType'));
  if (isnull(serviceType) || len(serviceType) != 1) continue;
  serviceType = serviceType[0];

  if ("ContentDirectory" >!< serviceType) continue;

  ctrlUrl = list_uniq(get_kb_list('upnp/'+port+'/service/'+service+'/controlURL'));
  if (isnull(ctrlUrl) || len(ctrlUrl) != 1) continue;
  ctrlUrl = ctrlUrl[0];

  payload = '<?xml version="1.0" encoding="utf-8" standalone="yes"?>' +
    '<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">' +
    '<s:Body>' +
    '<u:Browse xmlns:u="' + serviceType + '">' +
    '<ObjectID>0</ObjectID>' +
    '<BrowseFlag>BrowseDirectChildren</BrowseFlag>' +
    '<Filter>*</Filter>' +
    '<StartingIndex>0</StartingIndex>' +
    '<RequestedCount>10</RequestedCount>' +
    '<SortCriteria></SortCriteria>' +
    '</u:Browse>' +
    '</s:Body>' +
    '</s:Envelope>';

  soapAction = ('"' + serviceType + '#' + 'Browse' + '"');
  resp = http_send_recv3(method: 'POST',
                         item: ctrlUrl,
                         port: port,
                         content_type: 'text/xml;charset="utf-8"',
                         add_headers: make_array('Soapaction', soapAction),
                         data: payload,
                         host: get_host_ip(),
                         exit_on_fail: FALSE);

  if (isnull(resp) || '200 OK' >!< resp[0]) continue;

  rootxml = xmlparse(resp[2]);
  if (isnull(rootxml)) continue;

  body = xml_get_child(table:rootxml, name:'s:Body');
  if (isnull(body)) continue;

  browse = xml_get_child(table:body, name:'u:BrowseResponse');
  if (isnull(browse)) continue;

  result = xml_get_child(table:browse, name:'Result');
  if (isnull(result) || len(result["value"]) == 0) continue;

  # this represents an embedded-ish xml and we have to reparse.
  rootxml = xmlparse(result["value"]);
  if (isnull(rootxml)) continue;

  var containers = xml_get_children(table:rootxml, name:'container');
  if (isnull(containers) || len(containers) == 0) continue;

  vuln = TRUE;
  full_url = 'http://' + get_host_ip() + ':' + port + ctrlUrl;
  report += '\nNessus found a browsable file share at ' + full_url + '\n';
  report += 'displaying some top level directories:\n';
  foreach(container in containers)
  {
    title = xml_get_child(table:container, name:'dc:title');
    class = xml_get_child(table:container, name:'upnp:class');
    if (!isnull(title) && !isnull(class) && 'container' >< class['value'])
    {
      report += '\t/';
      report += title['value'];
      report += '\n';
    }
  }
}

if (!vuln) exit(0, 'The server at ' + location + ' is not affected.');
else security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
