#TRUSTED 623b31a41a8c75b2cd1488a22bcd0b1d4950caea1c49411e347e98d6e0f5fc2810c52d59359d1d460bf276af9f1d0e6c90f6d871e4b4b7a34860d3a791bc483123305b3ee352910c47b6b3558e960956222d9f8fd28916338e1eb4fdfa13bb55acd4d941ccd721b902b4705e492eac842f547cc0afab7ffad358c18102343ed94f95a616e847099247e3cdd8a7d6d144517f3c6a4544db0447983307808502c2286b0c9f23a02299eba1e172479853e19544c73130949f38bdf299ebcf607eec0e7901530175223247ad6b21dbf640fce749bab6cf7eabe5ca317d39406ddf3c752ea82d1b44d9f4a30ffa1894886dfa56909080b35fd172b24d94f8d8aa22f2887f428bfa65a03916c717f3833f48c1d96f8a7b813ce8e37da5c69c8c196549a067c9d8eceec676403c55b6f8afc64ba77b74aa7ea22a21c25bd32f41884f300f1d00d118eb9e54ede2db4d212974992abb0d20ca2a3f5e7215b1fa3adf0ddf6b125611bb8d465bd580ef690e05d5f11c9819ccc518df5d83224ec41f0456fe25edf15af2e7829af28436a188cfc20802fecc5b4bc6daa03804ef58fea18e8b315726294f4d91d8113dc02780f93cce78367dd1ce1bb6a5dedabc53b843ff2001e130b6f7cbd99a42f8861f3f898656a9816222279589ded4f9dc8738d259635d43e88c7ce05685c29b5f9a75d76c7d30a7d947ff24c9cffbdfa18e580c7cd6

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(94048);
 script_version("1.5");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

 script_xref(name:"CERT", value:"361684");

 script_name(english: "UPnP Internet Gateway Device (IGD) Port Mapping Listing");
 script_summary(english: "Lists the current IGD port mappings.");

 script_set_attribute(attribute:"synopsis", value:
"It was possible to list the port mappings created via UPnP IGD on the
remote device.");
 script_set_attribute(attribute:"description", value:
"According to its UPnP data, the remote device is a NAT router that
supports the Internet Gateway Device (IGD) Standardized Device Control
Protocol. Nessus was able to list 'port mappings' that redirect ports
from the device's external interface to the scanner address.

An unauthenticated, remote attacker can exploit this issue (e.g., via
JavaScript or a malicious Flash animation) to open holes in the
device's firewall. An unauthenticated, adjacent attacker has
unrestricted access to this interface.");
 script_set_attribute(attribute:"see_also", value:"https://github.com/filetofirewall/fof");
 script_set_attribute(attribute:"see_also", value:"https://www.gnucitizen.org/blog/flash-upnp-attack-faq/");
 script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Internet_Gateway_Device_Protocol");
 script_set_attribute(attribute:"solution", value:
"Disable IGD or restrict access to trusted networks.");
 script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");

 script_set_attribute(attribute:"vuln_publication_date", value: "2008/01/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/13");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "Misc.");

 script_copyright(english:"This script is Copyright (C) 2016-2018 Tenable Network Security, Inc.");

 script_dependencie("upnp_www_server.nasl");
 script_require_keys("upnp/www");

 exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('xml_func.inc');
include('audit.inc');
include('http.inc');

port = get_kb_item_or_exit('upnp/www');
location = get_kb_item_or_exit('upnp/'+port+'/location');
services = get_kb_list('upnp/'+port+'/service');

##
# Parses the 'GetGenericPortMappingEntryResponse' XML and
# extracts the relevant values to display to the user.
#
# @param xml the XML string we received via HTTP
# @return a string representation of the port mapping
##
function parse_mapping(xml)
{
  local_var rootxml = xmlparse(xml);
  if (isnull(rootxml)) return NULL;

  local_var body = xml_get_child(table:rootxml, name:'s:Body');
  if (isnull(body)) return NULL;

  local_var mapping = xml_get_child(table:body, name:'u:GetGenericPortMappingEntryResponse');
  if (isnull(mapping)) return NULL;

  local_var remoteHost = xml_get_child(table:mapping, name:'NewRemoteHost');
  if (isnull(remoteHost)) return NULL;
  if (isnull(remoteHost['value'])) remoteHost['value'] = '*';

  local_var extPort = xml_get_child(table:mapping, name:'NewExternalPort');
  if (isnull(extPort) || isnull(extPort['value'])) return NULL;

  local_var protocol = xml_get_child(table:mapping, name:'NewProtocol');
  if (isnull(protocol) || isnull(protocol['value'])) return NULL;

  local_var intPort = xml_get_child(table:mapping, name:'NewInternalPort');
  if (isnull(intPort) || isnull(intPort['value'])) return NULL;

  local_var intHost = xml_get_child(table:mapping, name:'NewInternalClient');
  if (isnull(intHost) || isnull(intHost['value'])) return NULL;

  local_var map_string = '\t[' + protocol['value'] + '] ' + remoteHost['value'] +
    ':' + extPort['value'] + ' -> ' + intHost['value'] + ':' + intPort['value'] + '\n';

  return map_string;
}

report = '';
vuln = FALSE;
foreach(service in services)
{
  serviceType = list_uniq(get_kb_list('upnp/'+port+'/service/'+service+'/serviceType'));
  if (isnull(serviceType) || len(serviceType) != 1) continue;
  serviceType = serviceType[0];

  if ("WANIPConnection" >!< serviceType && "WANPPPConnection" >!< serviceType) continue;

  ctrlUrl = list_uniq(get_kb_list('upnp/'+port+'/service/'+service+'/controlURL'));
  if (isnull(ctrlUrl) || len(ctrlUrl) != 1) continue;
  ctrlUrl = ctrlUrl[0];

  all_mappings = '';
  for (i = 0; i < 1024; i++)
  {
    payload = '<?xml version="1.0" encoding="utf-8" standalone="yes"?>' +
      '<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">' +
      '<s:Body>' +
      '<u:GetGenericPortMappingEntry xmlns:u="' + service + '">' +
      '<NewPortMappingIndex>' + i + '</NewPortMappingIndex>' +
      '</u:GetGenericPortMappingEntry>' +
      '</s:Body>' +
      '</s:Envelope>';

    soapAction = ('"' + service + '#' + 'GetGenericPortMappingEntry' + '"');
    resp = http_send_recv3(method: 'POST',
                           item: ctrlUrl,
                           port: port,
                           content_type: 'text/xml;charset="utf-8"',
                           add_headers:make_array('SOAPAction', soapAction),
                           data: payload,
                           host:get_host_ip(),
                           exit_on_fail: FALSE);

    if (isnull(resp) || '200 OK' >!< resp[0]) break;

    port_mapping = parse_mapping(xml:resp[2]);
    if (isnull(port_mapping)) break;
    all_mappings += port_mapping;
  }

  if (len(all_mappings) > 0)
  {
    vuln = TRUE;
    full_url = 'http://' + get_host_ip() + ':' + port + ctrlUrl;
    report += '\nThe remote device at ' + full_url + ' contains the following port mappings :\n';
    report += all_mappings;
  }
}

if (!vuln) exit(0, 'The server at ' + location + ' is not affected.');
else security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
