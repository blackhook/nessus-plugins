#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(104743);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_name(english:"TLS Version 1.0 Protocol Detection");
  script_summary(english:"Checks for the use of the TLS 1.0 protocol.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service encrypts traffic using an older version of TLS.");
  script_set_attribute(attribute:"description", value:
"The remote service accepts connections encrypted using TLS 1.0. TLS 1.0 has a
number of cryptographic design flaws. Modern implementations of TLS 1.0
mitigate these problems, but newer versions of TLS like 1.2 and 1.3 are
designed against these flaws and should be used whenever possible.

As of March 31, 2020, Endpoints that aren’t enabled for TLS 1.2
and higher will no longer function properly with major web browsers and major vendors.

PCI DSS v3.2 requires that TLS 1.0 be disabled entirely by June 30,
2018, except for POS POI terminals (and the SSL/TLS termination
points to which they connect) that can be verified as not being
susceptible to any known exploits.");
  script_set_attribute(attribute:"solution", value:
"Enable support for TLS 1.2 and 1.3, and disable support for TLS 1.0.");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-oldversions-deprecate-00");

  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"score from a more in depth analysis done by Tenable");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/22");

  script_cwe_id(327);

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_ciphers.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("byte_func.inc");
include("ssl_funcs.inc");

get_kb_item_or_exit("SSL/Supported");

# Get list of ports that use SSL or StartTLS.
var ports = get_ssl_ports();
if (isnull(ports) || max_index(ports) == 0)
  exit(1, "The host does not appear to have any TLS-based services.");

# intentionally changed var "ciphers" to "ciphrs" 
# gloabl var ciphers already exists in ssl_funcs.static
var port, encaps, ciphrs, tlsv1_cipher, tlsv1_encap, encap, cipher, report;
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

  tlsv1_encap = FALSE;
  tlsv1_cipher = FALSE;

  # First, determine if the server advertised any deprecated TLS/SSL versions
  foreach encap (encaps)
  {
    if (encap == ENCAPS_TLSv1)
      tlsv1_encap = TRUE;
  }

  if (!tlsv1_encap)
    continue;

  # Then, make sure that the deprecated version supports at least one cipher.
  # If zero ciphers are supported, the deprecated version cannot be used and no vulnerability exists.
  foreach cipher (ciphrs)
  {
    if (tlsv1_encap && cipher =~ "^TLS1_")
      tlsv1_cipher = TRUE;

    if (tlsv1_cipher)
      break;
  }

  report = NULL;
  if (tlsv1_encap && tlsv1_cipher)
  {
    report += 'TLSv1 is enabled and the server supports at least one cipher.';
    set_kb_item(name:'SSL/deprecated/TLSv1', value:port);
  }

  if (!isnull(report))
  {
    security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
  }
}
