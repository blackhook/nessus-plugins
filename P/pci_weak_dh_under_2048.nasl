#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(106459);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2015-4000");
  script_bugtraq_id(74733);
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Weak DH Key Exchange Supported (PCI DSS)");

  script_set_attribute(attribute:"synopsis", value:
"A service on the remote host supports a weak key exchange mechanism");
  script_set_attribute(attribute:"description", value:
"At least one of the services on the remote host supports a
Diffie-Hellman key exchange using a public modulus smaller than 2048
bits.

Diffie-Hellman key exchanges with keys smaller than 2048 bits do not
meet the PCI definition of strong cryptography as specified by
NIST Special Publication 800-57 Part 1.

Diffie-Hellman moduli of up to 1024 bits are considered practically
breakable by an attacker with very significant resources.");
  script_set_attribute(attribute:"see_also", value:"https://weakdh.org/");
  script_set_attribute(attribute:"solution", value:
"Consult the software's manual and reconfigure the service to use at
least 2048-bit DH parameters. Alternatively, disable DH and use only
Elliptic-curve Diffie-Hellman (ECDH) instead.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:X/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4000");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_logjam.nasl", "ssh_logjam.nasl");
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

ssl_ports = get_kb_list("PCI/weak_dh_ssl");
ssh_ports = get_kb_list("PCI/weak_dh_ssh");

if (isnull(ssl_ports) && isnull(ssh_ports))
  exit(0, "No affected SSH or SSL services were detected.");

if (isnull(ssl_ports))
  ssl_ports = [];
if (isnull(ssh_ports))
  ssh_ports = [];

foreach port (list_uniq(ssl_ports))
{
  length = get_kb_item("PCI/weak_dh_ssl/modlen/" + port);
  if (length >= 2048)
    continue;
  security_report_v4(
    severity:SECURITY_WARNING,
    port:port,
    extra:"The SSL/TLS service on port " + port + " uses a " + length + "-bit DH modulus."
  );
}

# ssh_logjam.nasl does not check for moduli smaller than 2048 bits,
# rather it checks that a 1024-bit modulus is supported.
# Operators *could* create a weird, barely-big-enough modulus like
# 1028-bit and this check wouldn't flag them.
foreach port (ssh_ports)
{
  supported = get_kb_item("PCI/weak_dh_ssh/moduli/" + port);
  # A little confusing; ssh_logjam.nasl sets a KB for either "group1",
  # "gex1024", or "both" if both gex1024 and group1 are supported.
  report = 'The SSH service on port ' + port + ' supports a weak DH modulus :\n';
  if (supported == "group1" || supported == "both")
    # It's called Oakley Group 2, but SSH protocol calls it group1. See RFC 4253 8.1.
    report += '  - The very common 1024-bit Oakley Group 2 DH modulus\n';
  if (supported == "gex1024" || supported == "both")
    report += '  - DH group exchange is enabled and 1024-bit parameters are allowed\n';

  security_report_v4(
    severity:SECURITY_WARNING,
    port:port,
    extra:report
  );
}
