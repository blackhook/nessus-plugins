#TRUSTED 9b54e3039f92e527e6a1508f7be5be9b2038847e7e8733f7bdcf46b459a7f7a06888a57d72d8b084e0c227f22182e61bb9ea8b3665b2a982dee861fec7f5a7b55e097d076bbff2d48f33ea55cc348520f9c0470d9429886755de6d8c6a9aed2cac1aecfbd8f4a22c08842e8a5ce186277b5e301e5fa478e351c45242c9e23c5308d26eaa2e47f8e2e3ffb89d9ad8e7278747fed064de92bf0012f238d782be4ed808fc420aa0c83f8e73f5e46f06091247de7d1ad3301f102b51a6a9acc71ca8143e70881e17fdfc6487b5db318ff2c658d96672dc5b82e8d007dfb24b0511bf68047276dda96499445863f209e11de09206c2713042680b5003722068ea0d391ccf81884aa228a5c75f5e9271e111ff444e87694261e76ae06c3fc46ea9298a978639a90daf30e8b9e14d7c0ddfc7b4e4c6abd9d8602ca4f99a8f5137ac4d81101c7203723e5cbfcb4b4b1966da8ac937561640fb64b66414b0208719738ab996af215a62d095dcfcfba0c103f4407108917175860de2153771821af2fd7213732484e0d2981b78012535b66a22ce6a439aefef007acbfeeeca48d970424af98e0e74b3d020be7d566384bbc67f6f3489eb69ca10367776a6b4d15c6afb070539752a57fb13723dda25df398fb50a98d94c7be25ef573c8922be8129578c6d20907eead3c07c2638bd9f1ca5f8f21b659c5ba108283c7b03e8ef3335fbe9d94
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(141118);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/26");

  script_name(english:"Target Credential Status by Authentication Protocol - Valid Credentials Provided");
  script_summary(english:"Reports protocols that have valid credentials provided.");

  script_set_attribute(attribute:"synopsis", value:
"Valid credentials were provided for an available authentication protocol.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to determine that valid credentials were provided for
an authentication protocol available on the remote target because it
was able to successfully authenticate directly to the remote target
using that authentication protocol at least once. Authentication was
successful because the authentication protocol service was available
remotely, the service was able to be identified, the authentication
protocol was able to be negotiated successfully, and a set of
credentials provided in the scan policy for that authentication
protocol was accepted by the remote service. See plugin output for
details, including protocol, port, and account.

Please note the following :

- This plugin reports per protocol, so it is possible for
  valid credentials to be provided for one protocol and not
  another. For example, authentication may succeed via SSH
  but fail via SMB, while no credentials were provided for
  an available SNMP service.

- Providing valid credentials for all available
  authentication protocols may improve scan coverage, but
  the value of successful authentication for a given
  protocol may vary from target to target depending upon
  what data (if any) is gathered from the target via that
  protocol. For example, successful authentication via SSH
  is more valuable for Linux targets than for Windows
  targets, and likewise successful authentication via SMB
  is more valuable for Windows targets than for Linux
  targets.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/15");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  # No dependencies, since this is an ACT_END plugin
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("spad_log_func.inc");
include("cred_func.inc");
include("lcx.inc");

function report_success(prefix, proto, db, port, user)
{
  if (lcx::check_localhost() && (proto == "SMB" || proto == "SSH"))
    return 0;

  local_var kb_prefix = prefix + proto + "/" + port;
  local_var report = '';

  report = get_credential_description(port:port, proto:proto);

  report = '\nNessus was able to log in to the remote host via the following :\n\n' + report;

  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);

  return 1;
}

function report_localhost()
{
  if (!lcx::check_localhost()) return 0;
  if (!get_kb_item("Host/local_checks_enabled")) return 0;
  local_var host_level_proto = get_kb_item("HostLevelChecks/proto");
  if (empty_or_null(host_level_proto) || host_level_proto != "local") return 0;

  local_var report = 'Nessus was able to execute commands on localhost.\n\n';

  security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);

  return 1;
}

successes = get_kb_list("Host/Auth/*/Success");

num_reported = 0;

pat = "^Host/Auth/([A-Za-z]+/[0-9]+)/.*";
foreach win (keys(successes))
{
  match = pregmatch(pattern:pat, string:win, icase:FALSE);
  if (isnull(match)) continue;

  protoport = match[1];

  tmp = split(protoport, sep:'/', keep:FALSE);
  num_reported += report_success(prefix:"Host/Auth/", proto:tmp[0], port:tmp[1], user:successes[win]);
}

if (num_reported == 0) num_reported += report_localhost();

if (num_reported == 0)
{
  if (lcx::svc_available())
    exit(0, "No authentication successes using user supplied credentials to report.");
  else exit(0, "No local checks ports or services were detected.");
}
