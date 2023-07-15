##
#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2021/11/18. Deprecated by plugin ID 132675 ssl_deprecated_ciphers_89.nasl.
##

include('compat.inc');

if (description)
{
  script_id(131290);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/19");

  script_name(english:"SSL/TLS Deprecated Ciphers (deprecated)");

  script_set_attribute(attribute:"synopsis", value:"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:"The remote host has open SSL/TLS ports which advertise 
deprecated cipher suites. The ciphers contained in these suites are no longer supported by most major ssl libraries
such as OpenSSL, NSS, Mbed TLS, and wolfSSL and, as such, should not be used for secure communication.

Nessus 8.9 and later no longer supports these ciphers.

This plugin was deprecated on 2021/11/18 and has been replaced with plugin ID 132675.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_ciphers.nasl");
  script_exclude_keys("global_settings/disable_test_ssl_based_services");
  exit(0);
}
exit(0, 'This plugin has been deprecated. Use plugin ID 132675 instead.');
