#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(153953);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/13");

  script_name(english:"SSH Weak Key Exchange Algorithms Enabled");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH server is configured to allow weak key exchange algorithms.");
  script_set_attribute(attribute:"description", value:
"The remote SSH server is configured to allow key exchange algorithms which are considered weak.

This is based on the IETF draft document Key Exchange (KEX) Method Updates and Recommendations for Secure Shell (SSH)
draft-ietf-curdle-ssh-kex-sha2-20. Section 4 lists guidance on key exchange algorithms that SHOULD NOT and MUST NOT be
enabled. This includes:

  diffie-hellman-group-exchange-sha1

  diffie-hellman-group1-sha1

  gss-gex-sha1-*

  gss-group1-sha1-*

  gss-group14-sha1-*

  rsa1024-sha1

Note that this plugin only checks for the options of the SSH server, and it does not check for vulnerable software
versions.");
  # https://datatracker.ietf.org/doc/html/draft-ietf-curdle-ssh-kex-sha2-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b02d91cd");
  script_set_attribute(attribute:"see_also", value:"https://datatracker.ietf.org/doc/html/rfc8732");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor or consult product documentation to disable the weak algorithms.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for weak key exchange");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_supported_algorithms.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

var port, all_algos, algo, weak_algos, weak_algo, enabled_weak_algos, report;

port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);

all_algos = get_kb_list('SSH/' + port + '/kex_algorithms');
if (isnull(all_algos))
  audit(AUDIT_NOT_DETECT, 'SSH support for known weak key exchange algorithms', port);

# from https://datatracker.ietf.org/doc/html/draft-ietf-curdle-ssh-kex-sha2-20 section 4
# diffie-hellman-group-exchange-sha1 | SHOULD NOT
# diffie-hellman-group1-sha1 | SHOULD NOT
# gss-gex-sha1-* | SHOULD NOT
# gss-group1-sha1-* | SHOULD NOT
# gss-group14-sha1-* | SHOULD NOT
# rsa1024-sha1 | MUST NOT

weak_algos = [
  'diffie-hellman-group-exchange-sha1',
  'diffie-hellman-group1-sha1',
  'gss-gex-sha1-',
  'gss-group1-sha1-',
  'gss-group14-sha1-',
  'rsa1024-sha1'
];

enabled_weak_algos = [];

foreach algo (all_algos)
{
  foreach weak_algo (weak_algos)
  {
    if (weak_algo >< algo)
      append_element(var:enabled_weak_algos, value:algo);
  }
}

if (max_index(enabled_weak_algos) == 0)
  audit(AUDIT_NOT_DETECT, 'SSH support for known weak key exchange algorithms enabled', port);

report =
  '\nThe following weak key exchange algorithms are enabled : \n' +
  '\n  ' + join(sort(enabled_weak_algos), sep:'\n  ') +
  '\n';

security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
