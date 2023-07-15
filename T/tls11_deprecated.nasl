#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157288);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_name(english:"TLS Version 1.1 Protocol Deprecated");

  script_set_attribute(attribute:"synopsis", value:
"The remote service encrypts traffic using an older version of TLS.");
  script_set_attribute(attribute:"description", value:
"The remote service accepts connections encrypted using TLS 1.1. TLS 1.1 lacks support for current and recommended
cipher suites. Ciphers that support encryption before MAC computation, and authenticated encryption modes such as GCM
cannot be used with TLS 1.1

As of March 31, 2020, Endpoints that are not enabled for TLS 1.2 and higher will no longer function properly with major
web browsers and major vendors.");
  script_set_attribute(attribute:"see_also", value:"https://datatracker.ietf.org/doc/html/rfc8996");
  # https://blog.pcisecuritystandards.org/are-you-ready-for-30-june-2018-sayin-goodbye-to-ssl-early-tls
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8ae820d");
  script_set_attribute(attribute:"solution", value:
"Enable support for TLS 1.2 and/or 1.3, and disable support for TLS 1.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score from an in depth analysis done by Tenable");
  script_cwe_id(327);

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_ciphers.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include('byte_func.inc');
include('ssl_funcs.inc');

get_kb_item_or_exit('SSL/Supported');

# Get list of ports that use SSL or StartTLS.
var ports = get_ssl_ports();
if (isnull(ports) || max_index(ports) == 0)
  exit(1, 'The host does not appear to have any TLS-based services.');

var port = branch(ports);

# Get the list of encapsulations supported by the port, through either SSL or StartTLS.
var encaps = get_kb_list('SSL/Transport/' + port);
if (!encaps)
  audit(AUDIT_HOST_NOT, 'affected');

var my_ciphers = get_kb_list('SSL/Ciphers/' + port);
if (isnull(my_ciphers))
  audit(AUDIT_HOST_NOT, 'affected');

my_ciphers = make_list(my_ciphers);
if (max_index(my_ciphers) == 0)
  audit(AUDIT_HOST_NOT, 'affected');

var tlsv11_encap = FALSE;
var tlsv11_cipher = FALSE;

# First, determine if the server advertised any deprecated TLS/SSL versions
foreach var encap (encaps)
{
  if (encap == COMPAT_ENCAPS_TLSv11)
    tlsv11_encap = TRUE;
}

if (!tlsv11_encap)
  audit(AUDIT_HOST_NOT, 'affected');

# Then, make sure that the deprecated version supports at least one cipher.
# If zero ciphers are supported, the deprecated version cannot be used and no vulnerability exists.
# There really are no TLS 1.1 ciphers it shares the same cipher support as TLS 1.0.
foreach var cipher (my_ciphers)
{
  if (cipher =~ "^TLS1_")
  {
    tlsv11_cipher = TRUE;
    break;
  }
}

if (tlsv11_cipher)
{
  var report = 'TLSv1.1 is enabled and the server supports at least one cipher.';
  set_kb_item(name:'SSL/deprecated/TLSv11', value:port);
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else
  audit(AUDIT_HOST_NOT, 'affected');
