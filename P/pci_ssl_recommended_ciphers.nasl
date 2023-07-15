#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159543);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_name(english:"SSL/TLS Recommended Cipher Suites (PCI DSS)");

  script_set_attribute(attribute:"synopsis", value:"The remote host advertises discouraged SSL/TLS ciphers.");
  script_set_attribute(attribute:"description", value:
"The remote host has open SSL/TLS ports which advertise discouraged cipher suites. It is recommended to only enable
support for the following cipher suites:

TLSv1.3:
  - 0x13,0x01 TLS13_AES_128_GCM_SHA256
  - 0x13,0x02 TLS13_AES_256_GCM_SHA384
  - 0x13,0x03 TLS13_CHACHA20_POLY1305_SHA256

TLSv1.2:
  - 0xC0,0x2B ECDHE-ECDSA-AES128-GCM-SHA256
  - 0xC0,0x2F ECDHE-RSA-AES128-GCM-SHA256
  - 0xC0,0x2C ECDHE-ECDSA-AES256-GCM-SHA384
  - 0xC0,0x30 ECDHE-RSA-AES256-GCM-SHA384
  - 0xCC,0xA9 ECDHE-ECDSA-CHACHA20-POLY1305
  - 0xCC,0xA8 ECDHE-RSA-CHACHA20-POLY1305
  - 0x00,0x9E DHE-RSA-AES128-GCM-SHA256
  - 0x00,0x9F DHE-RSA-AES256-GCM-SHA384
  - 0xCC,0xAA DHE_RSA_WITH_CHACHA20_POLY1305_SHA256

This is the recommended configuration for the vast majority of services, as it is highly secure and compatible with
nearly every client released in the last five (or more) years.");
  script_set_attribute(attribute:"see_also", value:"https://wiki.mozilla.org/Security/Server_Side_TLS");
  script_set_attribute(attribute:"see_also", value:"https://ssl-config.mozilla.org/");
  script_set_attribute(attribute:"solution", value:"Only enable support for recommended cipher suites.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score from an in depth analysis done by Tenable");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_ciphers.nasl");
  script_require_keys("Settings/PCI_DSS");
  script_exclude_keys("Settings/PCI_DSS_local_checks");
  exit(0);
}

include('ssl_tls_recommended_ciphers.inc');

if (!get_kb_item("Settings/PCI_DSS")) audit(AUDIT_PCI);

if (get_kb_item("Settings/PCI_DSS_local_checks"))
  exit(1, "This plugin only runs for PCI External scans.");

if (get_kb_item('global_settings/disable_test_ssl_based_services'))
  exit(1, 'Not testing SSL based services per user config.');

var ports_and_discouraged_ciphers = ssl_tls_ciphers::get_discouraged_ciphers();

if (empty_or_null(keys(ports_and_discouraged_ciphers)))
  audit(AUDIT_HOST_NOT, 'affected');

var report_header =
'The remote host has listening SSL/TLS ports which advertise the discouraged cipher suites outlined below:\n\n';

foreach var port (sort(keys(ports_and_discouraged_ciphers)))
{
  var report = report_header + cipher_report(ports_and_discouraged_ciphers[port]);
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
