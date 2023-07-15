#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(153588);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/05");

  script_name(english:"SSH SHA-1 HMAC Algorithms Enabled");
  script_summary(english:"SSH is configured to enable SHA-1 HMAC algorithms.");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH server is configured to enable SHA-1 HMAC algorithms.");
  script_set_attribute(attribute:"description", value:
"The remote SSH server is configured to enable SHA-1 HMAC algorithms.

Although NIST has formally deprecated use of SHA-1 for digital signatures, SHA-1 is still considered secure for HMAC as
the security of HMAC does not rely on the underlying hash function being resistant to collisions.

Note that this plugin only checks for the options of the remote SSH server.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_supported_algorithms.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include('ssh_sha1_hmac.inc');

var port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);

var algs_c2s = sort(ssh_sha1::get_macs(port:port, type:'client_to_server'));
var algs_s2c = sort(ssh_sha1::get_macs(port:port, type:'server_to_client'));

if (max_index(algs_c2s) == 0 && max_index(algs_s2c) == 0)
  audit(AUDIT_NOT_DETECT, 'An SSH server with SHA-1 HMAC alrogithms enabled', port);

var report = NULL;
if (report_verbosity > 0)
{
  if (max_index(algs_c2s) != 0)
  {
    report +=
      '\nThe following client-to-server SHA-1 Hash-based Message Authentication Code (HMAC) algorithms are supported : ' +
      '\n' +
      '\n  ' + join(sort(algs_c2s), sep:'\n  ') +
      '\n';
  }

  if (max_index(algs_s2c) != 0)
  {
    report +=
      '\nThe following server-to-client SHA-1 Hash-based Message Authentication Code (HMAC) algorithms are supported : ' +
      '\n' +
      '\n  ' + join(sort(algs_s2c), sep:'\n  ') +
      '\n';
  }
}

security_note(port:port, extra:report);
