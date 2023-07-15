#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106457);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/22");

  script_name(english:"Anonymous Key Exchanges Supported (PCI DSS)");
  script_summary(english:"Checks services for Anonymous DH or ECDH support");

  script_set_attribute(attribute:"synopsis", value:
"A service on the remote host supports an unauthenticated key exchange");
  script_set_attribute(attribute:"description", value:
"At least one of the SSL or TLS services on the remote host supports
an anonymous DH or anonymous ECDH cipher. When an anonymous cipher is
used, the client does not authenticate the server and an attacker may
intercept and modify encrypted traffic.");
  script_set_attribute(attribute:"solution", value:
"Consult the software's manual and reconfigure the service to disable
support for anonymous key exchanges.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score from an in depth analysis done by Tenable");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_anon_ciphers.nasl");
  script_require_keys("Settings/PCI_DSS");
  script_exclude_keys("Settings/PCI_DSS_local_checks");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Settings/PCI_DSS"))
  audit(AUDIT_PCI);

if (get_kb_item("Settings/PCI_DSS_local_checks"))
  exit(1, "This plugin only runs for PCI External scans.");

ports = get_kb_list("PCI/anon_keyex_ssl");
if (isnull(ports))
  exit(0, "No affected SSL services were detected.");

foreach port (list_uniq(ports))
{
  # The raw preformatted report from ssl_anon_ciphers.nasl
  report = get_kb_item("PCI/anon_keyex_ssl/report/" + port);
  security_report_v4(
    severity:SECURITY_WARNING,
    port:port,
    extra:
      'The SSL/TLS service on port ' + port + ' supports these anonymous ciphers :\n' + report
  );
}
