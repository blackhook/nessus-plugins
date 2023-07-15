#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121010);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_name(english:"TLS Version 1.1 Protocol Detection");
  script_summary(english:"Checks for the use of the TLS 1.1 protocol.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service encrypts traffic using an older version of TLS.");
  script_set_attribute(attribute:"description", value:
"The remote service accepts connections encrypted using TLS 1.1.
TLS 1.1 lacks support for current and recommended cipher suites.
Ciphers that support encryption before MAC computation, and
authenticated encryption modes such as GCM cannot be used with
TLS 1.1

As of March 31, 2020, Endpoints that are not enabled for TLS 1.2 
and higher will no longer function properly with major web browsers and major vendors.");
  script_set_attribute(attribute:"solution", value:
"Enable support for TLS 1.2 and/or 1.3, and disable support for TLS 1.1.");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-oldversions-deprecate-00");
  #https://blog.pcisecuritystandards.org/are-you-ready-for-30-june-2018-sayin-goodbye-to-ssl-early-tls
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8ae820d");

  script_cwe_id(327);

  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  exit(1, "The host does not appear to have any TLS-based services.");

var port, encaps, ciphrs, tlsv11_encap, tlsv11_cipher, encap, cipher, report; 
foreach port (ports)
{
  # Get the list of encapsulations supported by the port, through either SSL or StartTLS.
  encaps = get_kb_list("SSL/Transport/" + port);
  if (!encaps)
    continue;

  ciphrs = get_kb_list("SSL/Ciphers/" + port);
  if (isnull(ciphrs))
    continue;

  ciphrs = make_list(ciphrs);
  if (max_index(ciphrs) == 0)
    continue;

  tlsv11_encap = FALSE;
  tlsv11_cipher = FALSE;

  # First, determine if the server advertised any deprecated TLS/SSL versions
  foreach encap (encaps)
  {
    if (encap == COMPAT_ENCAPS_TLSv11)
      tlsv11_encap = TRUE;
  }

  if (!tlsv11_encap)
    continue;

  # Then, make sure that the deprecated version supports at least one cipher.
  # If zero ciphers are supported, the deprecated version cannot be used and no vulnerability exists.
  # There really are no TLS 1.1 ciphers it shares the same cipher support as TLS 1.0.
  foreach cipher (ciphrs)
  {
    if (tlsv11_encap && cipher =~ "^TLS1_")
      tlsv11_cipher = TRUE;

    if (tlsv11_cipher)
      break;
  }

  report = NULL;
  if (tlsv11_encap && tlsv11_cipher)
  {
    report += 'TLSv1.1 is enabled and the server supports at least one cipher.';
    set_kb_item(name:'SSL/deprecated/TLSv11', value:port);
  }

  if (!isnull(report))
  {
    # we are keeping the severity as None / Security note for the time being,
    # as a vuln here would make customers fail PCI
    # please check the following document regarding this:
    # https://www.pcisecuritystandards.org/documents/Migrating_from_SSL_Early_TLS_Information%20Supplement_v1.pdf
    security_report_v4(severity:SECURITY_NOTE, port:port, extra:report);
  }
}
