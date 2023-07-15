#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131127);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/07");

  script_name(english:"SSLv2-Only Open Ports");
  script_summary(english:"Checks if the remote host has any open ports which solely support SSLv2");

  script_set_attribute(attribute:"synopsis", value:"The remote service encrypts communications with an unsupported
protocol.");
  script_set_attribute(attribute:"description", value:"This plugin detects if the remote host has any open ports which
only support SSLv2. This protocol has been deprecated since 2011 because of security vulnerabilities and most major SSL
libraries such as OpenSSL, NSS, Mbed TLS, and wolfSSL do not provide this functionality in their latest versions.

Nessus 8.9 and later no longer supports SSLv2.");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc6176");
  script_set_attribute(attribute:"solution", value:"Upgrade encryption protocol used for SSL/TLS traffic to SSLv3,
TLS1.0, TLS1.1, TLS1.2, or TLS1.3");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_versions.nasl");
  script_exclude_keys("global_settings/disable_test_ssl_based_services");
  exit(0);
}

include('audit.inc');
include('lists.inc');
include('ssl_funcs.inc');

if (get_kb_item('global_settings/disable_test_ssl_based_services'))
  exit(1, 'Not testing SSL based services per user config.');

kb_base = 'SSL/Transport/';
sslv2_only_ports = [];
foreach port(get_ssl_ports())
{
  if (max_index(keys(get_kb_list(kb_base + port))) == 1 && get_kb_item(kb_base + port) == ENCAPS_SSLv2)
    collib::push(port, list:sslv2_only_ports);
}

if (max_index(sslv2_only_ports) == 0)
  audit(AUDIT_HOST_NOT, 'affected');

report = 'This port only supports SSLv2, which is deprecated since 2011 and no longer supported in Nessus 8.9 or later.';

foreach port(sslv2_only_ports)
{
  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
}
