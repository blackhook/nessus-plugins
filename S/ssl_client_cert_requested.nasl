#TRUSTED 1a2d5a148949de809747a523fa6df3921b6259fd9689fdd04141fe8ffbb3b746604ee24df4e91d37dc815464043be27908b9ab5f6e62652fe8845a75aded4d75ee99ff308cab5073e1d9c706fa9603290355387ce25e5fde16e8b192aaba9630243afd041b6bfa0b363c108fb357e2f6ac87b4eb6e6c9b6b813a347d6e97d7eaa7a8988a519e9ab511d4f7e3157736906787e28e887b560320d06ab997a2229a940a2c5cf8b2f1d3301a8c2a25645249221f7540be91d54760a1688c11497bcfcd340aae9e0a08ad2b533e401aea2f1547c63b6fa1b28ca73e9f6a042ae7c5202ae64960f80f6fee345fa88193b0ecb71161d38932c0ed2ede0b9ef463f95085a7f26654b55ece5641dfad1680d3dbb8f67003e3c4e418d18b1d9daf7accad79c0ed4d95d7bb8f07c322addedc39c6849570bcb94061754d4060c97ec3516bfc02f3aaf5e08cee3d8dd7088d4a05e033a1e17bb7b7ff21e82dee050dabfe2c70a383c786f3b96d8e82b3ffb84a418f1ba976a9ed9c23dc3f11ddd0004669bf4f0fcfb91016985d1216d35eaf32abe4c2b7e58ed9bfeddbe5b99ffec17885e792182cab120486a1142de2e9da28d0fc3a408d38f27fcf2c1658c9a165e7463345c348e67f9d5d81d238f7603d34560a2a3f4962fda07607eb7212f391b74b6a1aac03d3b9b514e81939a9f228a0a174e925bf5b0cc1f8cb2ee9484346af74a4ef
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(35297);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"SSL Service Requests Client Certificate");

  script_set_attribute(attribute:"synopsis", value:
"The remote service requests an SSL client certificate.");
  script_set_attribute(attribute:"description", value:
"The remote service encrypts communications using SSL/TLS, requests a
client certificate, and may require a valid certificate in order to
establish a connection to the underlying service.");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2009-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl", "ssl_supported_versions.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("ftp_func.inc");
include("kerberos_func.inc");
include("ldap_func.inc");
include("misc_func.inc");
include("nntp_func.inc");
include("smtp_func.inc");
include("telnet2_func.inc");
include("rsync.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

get_kb_item_or_exit("SSL/Supported");

ports = get_ssl_ports(fork:FALSE);
if(isnull(ports)) ports = make_list();

if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery"))
{
  unknown_ports = get_kb_list("Services/unknown");
  if(!isnull(unknown_ports))
    ports = make_list(ports, unknown_ports);
}

ports = add_port_in_list(list:ports, port:443);
ports = add_port_in_list(list:ports, port:1241);

ports = list_uniq(ports);
if(max_index(ports) == 0) exit(0, "No applicable listening ports found.");

port = branch(ports);

set_byte_order(BYTE_ORDER_BIG_ENDIAN);

versions = get_kb_list('SSL/Transport/'+port);

if(isnull(versions))
  versions = make_list(ENCAPS_SSLv3, ENCAPS_TLSv1, COMPAT_ENCAPS_TLSv11, COMPAT_ENCAPS_TLSv12);

report_encaps = make_list();

foreach encaps (versions)
{
  soc = open_sock_ssl(port);
  if (!soc)
    audit(AUDIT_SOCK_FAIL, port, "SSL");

  if(encaps == ENCAPS_SSLv3)
    ssl_ver = SSL_V3;
  else if(encaps == ENCAPS_TLSv1)
    ssl_ver = TLS_10;
  else if(encaps == COMPAT_ENCAPS_TLSv11)
    ssl_ver = TLS_11;
  else if(encaps == COMPAT_ENCAPS_TLSv12)
    ssl_ver = TLS_12;
  else continue; # we don't support any other ssl version

  ssl_ver = mkword(ssl_ver);

  hellodone = NULL;
  client_cert_requested = FALSE;

  hello = client_hello(
    version    : ssl_ver,
    v2hello    : FALSE
  );
 
  send(socket:soc, data:hello);

  while(1)
  {
    recs = "";
    repeat
    {
      rec = recv_ssl(socket:soc);
      if (isnull(rec)) break;
      recs += rec;
    } until (!socket_pending(soc));

    if(!recs) break;

    client_cert_requested = ssl_find(
      blob:recs,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_CERTIFICATE_REQUEST
    );

    if(client_cert_requested) break;

    hellodone = ssl_find(
      blob:recs,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO_DONE
    );

    if(hellodone) break;
  }

  close(soc);

  if(!client_cert_requested) continue;

  if (encaps == ENCAPS_SSLv3) encaps_str = 'SSLv3';
  else if (encaps == ENCAPS_TLSv1) encaps_str = 'TLSv1';
  else if (encaps == COMPAT_ENCAPS_TLSv11) encaps_str = 'TLSv11';
  else if (encaps == COMPAT_ENCAPS_TLSv12) encaps_str = 'TLSv12';

  report_encaps = make_list(report_encaps, encaps_str);
}

if(max_index(report_encaps) == 0)
  exit(0, "The service on port " + port + " does not request any SSL client certificates.");

report_str = join(report_encaps, sep:"/");

if(report_str[0] == 'S') report_str = 'An ' + report_str;
else report_str = 'A ' + report_str;

set_kb_item(name:'Services/ssl_client_cert_requested/' + port, value:report_str);
# optimization KB
replace_kb_item(name:'Services/ssl_client_cert_requested', value:TRUE);

report_str +=  ' server is listening on this port that requests a client certificate.\n';

security_report_v4(port:port, extra:'\n' + report_str, severity:SECURITY_NOTE);
