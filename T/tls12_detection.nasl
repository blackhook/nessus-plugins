#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(136318);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/04");

  script_name(english:"TLS Version 1.2 Protocol Detection");
  script_summary(english:"Checks for the use of the TLS 1.2 protocol.");
  script_set_attribute(attribute:"synopsis", value:
"The remote service encrypts traffic using a version of TLS.");
  script_set_attribute(attribute:"description", value:
"The remote service accepts connections encrypted using TLS 1.2.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:
"N/A");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc5246");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_ciphers.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");
include("audit.inc");

get_kb_item_or_exit("SSL/Supported");

# Get list of ports that use SSL or StartTLS.
ports = get_ssl_ports();
if (isnull(ports) || max_index(ports) == 0)
  exit(1, "The host does not appear to have any TLS-based services.");

foreach port (ports)
{
  # Get the list of encapsulations supported by the port, through either SSL or StartTLS.
  encaps = get_kb_list("SSL/Transport/" + port);
  if (!encaps)
    continue;

  ciphers = get_kb_list("SSL/Ciphers/" + port);
  if (isnull(ciphers))
    continue;

  ciphers = make_list(ciphers);
  if (max_index(ciphers) == 0)
    continue;

  tlsv12_encap = FALSE;
  tlsv12_cipher = FALSE;

  # Determine if the server advertises TLSv1.2.
  foreach encap (encaps)
  {
    if (encap == COMPAT_ENCAPS_TLSv12)
      tlsv12_encap = TRUE;
  }

  if (!tlsv12_encap)
    continue;

  # Then, make sure that the version supports at least one cipher.
  # If zero ciphers are supported, the version cannot be used.
  foreach cipher (ciphers)
  {
    if (tlsv12_encap && cipher =~ "^TLS12_")
      tlsv12_cipher = TRUE;

    if (tlsv12_cipher)
      break;
  }

  report = NULL;
  if (tlsv12_encap && tlsv12_cipher)
  {
    report += 'TLSv1.2 is enabled and the server supports at least one cipher.';
  }

  if (!isnull(report))
  {
    security_report_v4(severity:SECURITY_NOTE, port:port, extra:report);
  }
}
