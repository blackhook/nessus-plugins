#TRUSTED 0b4900cb2e00cd8d8e57d0e4c4016deded2acd1c1d3948b818f9bd7143f9207f34756f7092a2b8414038e1f474995a67c1c4549f42a6b5241ec4b3356bbb9c836c412cb04b1ad1482b499b40210cb8fcecad22603bbba3394926f04022b5c6af31148e9d249705d30f8dab47d031947980f181af8d6f94df3c438b9fc30100b606b63cafc87bb78592e182529bf9e2540d41cb7ca66fa4ff7666776d834090422b056abdfe4facfd83c2007030badf767e15ab362e95fb6da3ee09acf98aa6e479d33fd1e971018662b499d75d4bc408de5dc5c95ff0b61bf06ed9eab27cf9fb2ffddc5e671cc64fd9b1ffef5b3e81bda9a24566a906c6ae8b10e317086f66f5fca5395181f2b1906994c1356583c0e26121d825a589df9c3fd6ad43efa97c75077ef2607e55848e487b27c75e3839ca4146f3a598e151ea3fca3b719b34686a3a6d329e093beb551596ec5ea7aea4d306bdef5a8dbbb0aab13d0614fd507cbdbc54a86b6f0498531aaca87b6f03ce91cd6a32f6004aa9837000e54700856360b6be62a7558d11c4167ea1bd99d2cf3e3c4ffb87d3d3a065c8931a7aaf5fc617c5e8bf21a1bd3f01f8d2ccca7c178d8d5c1dee544c80c51daab2d2746adbfb97e784c1bf5e7930570b7a5bca459ca47c44e6c9ec5d7644dfbdce7a16f3b6b1676572233003fffdd518cc680586bfebaa82b434fdfdd565e1b74d5bf24ac11e69
#TRUST-RSA-SHA256 25f6e3f048cb15513e959060b083dd9dadd25f0bc1fc9ce2cd1d10ecc55512f9fd67d527d3e9f95c50e1d31061b3340d5833c72874d142b651a3ce0905a62fceb5c401c3ea22d4f1b07eb0383f7b6e9a0ec9d9be1233e4476062a7ec663f9e7a68fa088409050da7edacf13d28050a62750de35b712ffaf1cb2612090a6d4b2eaee3e942e0ababe7a0f1d2aae8f22e418dc55eb9615ed3113b9f127cc8248ae915000bb02c8b979181b6cfe2fd1819b6ec0cde221ab3ef1b26924c2eff296418ccf2fb3e39ecec49ad50416613fe90504dac635777cf1e4be152469d1b16c58934adf72a94f0d46de8f68ceb8f6474cf9c5e87aa89267e7d0c39339bd6a1821eeff7d62006ffa0bf7097d7826fc2a7b55863791e4d3f236aad16ac657d1d20d76206407efbdf36a6c1493f759a3911c43c88e71afed6a90c2664fee430bbc9e42ce106ff2c7514be8d5f04d391e5d52fc33b018934ce4f755a453a8fe6c29efe633110286cf682476e8dee7fbde7fab6e88304cb346147e102024f1fb932abe358ae170477c8b63324a7ccb31438a66cc5a6e407124a044e713621428414785fd5d0f650b14b40116800d5ffc5c034910380fa7d1235b8f7a3872c480c3f2a20bc4de9e08d9cd384f75b27cef83bb5370ad18452e5c3cbcd5e5864985a082a427a9424155a3bbe90d874dd63b2bf12824c3260f8f7adad592a1e96caad98c326
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("get_local_mac_addr")) exit(0);
if (! defined_func("inject_packet")) exit(0);
include('deprecated_nasl_level.inc');
include("compat.inc");

if(description)
{
  script_id(35713);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/10");

  script_name(english:"Scan for UPnP hosts (multicast)");

  script_set_attribute(attribute:"synopsis", value:
"This machine is a UPnP client.");
  script_set_attribute(attribute:"description", value:
"This machine answered to a multicast UPnP NOTIFY packet by trying to 
fetch the XML description that Nessus advertised.");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2009-2023 Tenable Network Security, Inc.");

  script_exclude_keys("/tmp/UDP/1900/closed");

  exit(0);
}

include('misc_func.inc');
include('byte_func.inc');

if ( (!get_kb_item("Host/udp_scanned") || !get_kb_item("Host/UDP/scanned")) &&
    ! get_kb_item("global_settings/thorough_tests") ) exit(0);

if ( TARGET_IS_IPV6 ) exit(0);	# TBD

if ( safe_checks() ) exit(0); # Switch issues
if (islocalhost()) exit(0);
if (!islocalnet())exit(0);
if (! get_udp_port_state(1900) || get_kb_item("/tmp/UDP/1900/closed")) exit(0);
if (! service_is_unknown(port: 1900, ipproto: "udp")) exit(0);

myaddr = compat::this_host();
dstaddr = get_host_ip();
returnport = rand() % 32768 + 32768;

data = strcat(
'NOTIFY * HTTP/1.1\r\n',
'HOST: 239.255.255.250:1900\r\n',
'CACHE-CONTROL: max-age=1800\r\n',
'LOCATION: http://', myaddr, ':', returnport, '/gatedesc.xml\r\n',
'NT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n',
'NTS: ssdp:alive\r\n',
'SERVER: Linux/2.6.26-hardened-r9, UPnP/1.0, Portable SDK for UPnP devices/1.6.6\r\n',
'X-User-Agent: redsonic\r\n',
'USN: uuid:75802409-bccb-40e7-8e6c-fa095ecce13e::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n',
'\r\n' );

len = strlen(data);

ip = forge_ip_packet(ip_hl: 5, ip_v: 4, ip_tos: 0, ip_len: 20,
   ip_id: rand(), ip_off: 0, ip_ttl: 64, ip_p: IPPROTO_UDP,
   ip_src: myaddr, ip_dst: '239.255.255.250');

udp = forge_udp_packet(ip: ip, uh_sport: rand() % 32768 + 32768, uh_dport: 1900,
 uh_ulen :8 + len, data: data);
if ( defined_func("datalink") ) 
{
 if ( datalink() != DLT_EN10MB ) exit(0);
}

macaddr   = get_local_mac_addr();

ethernet = '\x01\x00\x5E\x7F\xFF\xFA'	# Multicast address
	 + macaddr
	 + mkword(0x0800)		# Protocol = IPv4
	 + udp;
filter = strcat("tcp and src ", dstaddr, " and dst port ", returnport);

for (i = 0; i < 60; i ++)
{
  r = inject_packet(packet: ethernet, filter:filter, timeout: 1);
  if (strlen(r) > 14 + 20 + 20)
  {
    flags = get_tcp_element(tcp: substr(r, 14), element:"th_flags");
    if (flags & TH_SYN)
    {
       security_note(port:1900,protocol:"udp");
       register_service(port: 1900, proto: "upnp-client", ipproto: "udp");
    }
    exit(0);     
  }
}
