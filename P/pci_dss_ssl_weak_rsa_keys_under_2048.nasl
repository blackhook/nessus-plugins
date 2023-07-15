#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73459);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/22");

  script_name(english:"SSL Certificate Chain Contains RSA Keys Less Than 2048 bits (PCI DSS)");
  script_summary(english:"Checks that the certificate chain has no RSA keys under 2048 bits");

  script_set_attribute(attribute:"synopsis", value:
"The X.509 certificate chain used by this service contains certificates
with RSA keys shorter than 2048 bits.");
  script_set_attribute(attribute:"description", value:
"At least one of the X.509 certificates sent by the remote host has a
key that is shorter than 2048 bits. According to industry standards
set by the Certification Authority/Browser (CA/B) Forum, certificates
issued after January 1, 2014 must be at least 2048 bits.

Some browser SSL implementations may reject keys less than 2048 bits
after January 1, 2014. Additionally, some SSL certificate vendors may
revoke certificates less than 2048 bits before January 1, 2014.

Note that Nessus will not flag root certificates with RSA keys less
than 2048 bits if they were issued prior to December 31, 2010, as the
standard considers them exempt.");
  script_set_attribute(attribute:"see_also", value:"https://www.cabforum.org/wp-content/uploads/Baseline_Requirements_V1.pdf");
  script_set_attribute(attribute:"solution", value:
"Replace the certificate in the chain with the RSA key less than 2048
bits in length with a longer key, and reissue any certificates signed
by the old certificate.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score from an in depth analysis done by Tenable");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2014-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_weak_rsa_keys_under_2048.nasl");
  script_require_keys("SSL/Chain/WeakRSA_Under_2048", "Settings/PCI_DSS");
  script_exclude_keys("Settings/PCI_DSS_local_checks");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Settings/PCI_DSS")) audit(AUDIT_PCI);

if (get_kb_item("Settings/PCI_DSS_local_checks"))
  exit(1, "This plugin only runs for PCI External scans.");

# Get the port that has weak RSA keys from the KB.
key = "SSL/Chain/WeakRSA_Under_2048";
port = get_kb_item_or_exit(key);

if (report_verbosity > 0) security_warning(port:port, extra:get_kb_item_or_exit("/tmp/PCI/ssl_weak_rsa_keys/"+port));
else security_warning(port);
