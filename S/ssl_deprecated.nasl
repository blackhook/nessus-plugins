#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(20007);
  script_version("1.34");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/04");

  script_name(english:"SSL Version 2 and 3 Protocol Detection");
  script_summary(english:"Checks for the use of a deprecated SSL protocol.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service encrypts traffic using a protocol with known
weaknesses.");
  script_set_attribute(attribute:"description", value:
"The remote service accepts connections encrypted using SSL 2.0 and/or
SSL 3.0. These versions of SSL are affected by several cryptographic
flaws, including:

  - An insecure padding scheme with CBC ciphers.

  - Insecure session renegotiation and resumption schemes.

An attacker can exploit these flaws to conduct man-in-the-middle
attacks or to decrypt communications between the affected service and
clients.

Although SSL/TLS has a secure means for choosing the highest supported
version of the protocol (so that these versions will be used only if
the client or server support nothing better), many web browsers
implement this in an unsafe way that allows an attacker to downgrade
a connection (such as in POODLE). Therefore, it is recommended that
these protocols be disabled entirely.

NIST has determined that SSL 3.0 is no longer acceptable for secure
communications. As of the date of enforcement found in PCI DSS v3.1,
any version of SSL will not meet the PCI SSC's definition of 'strong
cryptography'.");
  script_set_attribute(attribute:"see_also", value:"https://www.schneier.com/academic/paperfiles/paper-ssl.pdf");
  # https://support.microsoft.com/en-us/help/187498/how-to-disable-pct-1-0-ssl-2-0-ssl-3-0-or-tls-1-0-in-internet-informat
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b06c7e95");
  # https://web.archive.org/web/20140909130341/http://www.linux4beginners.info/node/disable-sslv2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?247c4540");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  # https://www.pcisecuritystandards.org/pdfs/15_02_12_PCI_SSC_Bulletin_on_DSS_revisions_SSL_update.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d15ba70");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  # TLS Fallback Signaling Cipher Suite Value (SCSV)
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc7507");
  # Deprecating Secure Sockets Layer Version 3.0
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc7568");
  script_set_attribute(attribute:"solution", value:
"Consult the application's documentation to disable SSL 2.0 and 3.0.
Use TLS 1.2 (with approved cipher suites) or higher instead.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"score from a more in depth analysis done by Tenable");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2004-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_ciphers.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

get_kb_item_or_exit("SSL/Supported");

# Get list of ports that use SSL or StartTLS.
ports = get_ssl_ports();
if (isnull(ports) || max_index(ports) == 0)
  exit(1, "The host does not appear to have any SSL-based services.");

foreach port (ports)
{
  # Avoid a false positive that can be caused by certain Citrix devices.
  banner = get_kb_item("www/banner/"+port);
  citrix = "SSL protocol version that your browser uses is SSLv2 and it is not compatible with the server settings.";
  citrix_device = FALSE;
  if (banner && citrix >< banner)
    citrix_device = TRUE;

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

  sslv2_encap = FALSE;
  sslv2_cipher = FALSE;
  sslv3_encap = FALSE;
  sslv3_cipher = FALSE;

  # First, determine if the server advertised any deprecated TLS/SSL versions
  foreach encap (encaps)
  {
    if (!citrix_device && encap == ENCAPS_SSLv2)
      sslv2_encap = TRUE;
    else if (encap == ENCAPS_SSLv3)
      sslv3_encap = TRUE;
  }

  if (!sslv2_encap && !sslv3_encap)
    continue;

  # Then, make sure that the deprecated version supports at least one cipher.
  # If zero ciphers are supported, the deprecated version cannot be used and no vulnerability exists.
  sslv2_ciphers = [];
  sslv3_ciphers = [];
  foreach cipher (ciphers)
  {
    if (sslv2_encap && cipher =~ "^SSL2_")
    {
      append_element(var:sslv2_ciphers, value:cipher);
      sslv2_cipher = TRUE;
    }
    # ssl_supported_versions.nasl assumes any non-SSLv2 or non TLS 1.2 or higher cipher can be used with SSLv3
    else if (sslv3_encap && (cipher =~ "^SSL3_" || cipher =~ '^TLS1_'))
    {
      append_element(var:sslv3_ciphers, value:cipher);
      sslv3_cipher = TRUE;
    }
  }

  report = NULL;
  if (sslv2_encap && sslv2_cipher)
  {
    report += '\n- SSLv2 is enabled and the server supports at least one cipher.\n';
    report += cipher_report(sslv2_ciphers);
    set_kb_item(name:'SSL/deprecated/SSLv2', value:port);
  }
  if (sslv3_encap && sslv3_cipher)
  {
    report += '\n- SSLv3 is enabled and the server supports at least one cipher.\n';
    report += '\tExplanation: TLS 1.0 and SSL 3.0 cipher suites may be used with SSLv3\n\n';
    report += cipher_report(sslv3_ciphers);
    set_kb_item(name:'SSL/deprecated/SSLv3', value:port);
  }

  if (!isnull(report))
  {
    security_hole(port:port, extra:report);
  }
}
