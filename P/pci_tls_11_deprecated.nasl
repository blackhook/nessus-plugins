#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139414);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/07");

  script_name(english:"TLS Version 1.1 Protocol Detection (PCI DSS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote service encrypts traffic using a protocol with known
weaknesses.");
  script_set_attribute(attribute:"description", value:
"The remote service accepts connections encrypted using TLS 1.1. This
version of TLS is affected by multiple cryptographic flaws. An
attacker can exploit these flaws to conduct man-in-the-middle attacks
or to decrypt communications between the affected service and clients.");
  script_set_attribute(attribute:"solution", value:
"All processing and third party entities - including Acquirers,
Processors, Gateways and Service Providers must provide a TLS 1.2 or
greater service offering by June 2018. All processing and third party
entities must cutover to a secure version of TLS (as defined by NIST)
effective June 2018.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score from an in depth analysis done by Tenable");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_ciphers.nasl", "tls11_detection.nasl");
  script_require_keys("SSL/Supported", "Settings/PCI_DSS");
  script_exclude_keys("Settings/PCI_DSS_local_checks");

  exit(0);
}

include('ssl_funcs.inc');
include('obj.inc');

if (!get_kb_item('Settings/PCI_DSS')) audit(AUDIT_PCI);
if (get_kb_item('Settings/PCI_DSS_local_checks'))
  exit(1, 'This plugin only runs for PCI External scans.');

get_kb_item_or_exit('SSL/Supported');

# Get list of ports that use SSL or StartTLS.
ports = get_ssl_ports();
if (isnull(ports) || max_index(ports) == 0)
  exit(1, 'The host does not appear to have any TLS-based services.');

tlsv11_ports = get_kb_list('SSL/deprecated/TLSv11');

reported_at_least_once = FALSE;
foreach port (ports)
{
  if (obj_in_list(list:tlsv11_ports, item:port))
  {
    security_hole(port:port, extra:'TLSv1.1 is enabled on port ' + port + ' and the server supports at least one cipher.');
    reported_at_least_once = TRUE;
  }
}

if (!reported_at_least_once)
  exit(0, 'None of the detected SSL/TLS services support TLSv1.1');
