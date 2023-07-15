#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106458);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id("CVE-2013-2566", "CVE-2015-2808");
  script_bugtraq_id(58796, 73684);

  script_name(english:"SSL/TLS Services Support RC4 (PCI DSS)");
  script_summary(english:"Checks that no services support RC4");

  script_set_attribute(attribute:"synopsis", value:
"A service on the remote host supports RC4");
  script_set_attribute(attribute:"description", value:
"At least one of the SSL or TLS services on the remote host supports
the use of RC4 for encryption.

RC4 does not meet the PCI definition of strong cryptography as defined
by NIST Special Publication 800-57 Part 1.

The RC4 cipher is flawed in its generation of a pseudo-random stream
of bytes so that a wide variety of small biases are introduced into
the stream, decreasing its randomness. If plaintext is repeatedly
encrypted (e.g., HTTP cookies), and an attacker is able to obtain many
(i.e., tens of millions) ciphertexts, the attacker may be able to
derive the plaintext.");
  script_set_attribute(attribute:"see_also", value:"https://www.rc4nomore.com");
  script_set_attribute(attribute:"see_also", value:"https://blog.pcisecuritystandards.org/migrating-from-ssl-and-early-tls");
  script_set_attribute(attribute:"solution", value:
"Consult the software's manual and reconfigure the service to disable
support for RC4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2808");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_rc4_supported_ciphers.nasl");
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

# Does not check SSH, because the SSH plugin for weak ciphers already
# flags RC4 and has a CVSS >= 4.0.

ports = get_kb_list("PCI/ssl_rc4_supported");
if (isnull(ports))
  exit(0, "No affected SSL services were detected.");

foreach port (list_uniq(ports))
{
  # This is the raw, preformatted report that ssl_rc4_supported_ciphers.nasl generates.
  report = get_kb_item("PCI/ssl_rc4_supported/report/" + port);
  security_report_v4(
    severity:SECURITY_WARNING,
    port:port,
    extra:'The SSL/TLS service on port ' + port + ' supports the following RC4 ciphers :\n' + report
  );
}
