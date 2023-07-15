#TRUSTED b2a27c93be6473bb6dbcc57df55880a559425a1a747a520754f95bef850952121a28b9481cb79c4cb843633088dd4025faf00bfd5237039551555f595f4dd0dbb7ccb547ae7f7b4e780318dd686970a70605d229954f9e3d893f9da68d481454cf84cb8b9e79227c22a1b29751b43a0d892e6c7a602fd6ce52cbc19ea2a49a887c88fe86eabf0c92f13828d827fa8b32638592582dc68de6078b8ed423f3185d60817053e9b1001f18d26143b03660adfe234ffe9be33f40bdc5a3eff72324b5ed05a2b3614fc226c6123e7a15b6ff000acd9ff38a524ba9d7709f99cc42e466b7c3cde2aa0e37e769bd2034e07f7d74260af9d29c237f252bfcf6068206db1f19fd48467f12c04cf0303d35adb1c95791b529967fca56b6ed96c9169e986a8e0205aa6f1319d3d682127459281c095a7e62ee104989f95ef9b641829eb1d8ce562173db2c4b314511783692529773e02006fcfddc4e345abdfc93cfb7ea1d3b6dc0845b7509a41afb3c81beb27ec54e2c978b5bd602de5284d510ca9998bd6d503751cd143854594bbdcb49cacfaf30abc1f403ac3c41f87982b493c60496fd23d3ad9af1d543dd0ea37f39d6050849d7e4b01501f17096f5079d97c952397ce5bdb7a4ddff9df60f966e564f94085b7af95ccb54d0e5ea1ea8892cdf7bd4eb08f82ac845cc1bc0a9c6426401469dd1a08aa8af610b98283a53ce97cabc59d3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110095);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/26");

  script_xref(name:"IAVB", value:"0001-B-0520");

  script_name(english:"Target Credential Issues by Authentication Protocol - No Issues Found");
  script_summary(english:"Reports protocols with valid credentials and no credential issues found.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to log in to the remote host using the provided
credentials. No issues were reported with access, privilege, or
intermittent failure.");
  script_set_attribute(attribute:"description", value:
"Valid credentials were provided for an authentication protocol on the
remote target and Nessus did not log any subsequent errors or failures
for the authentication protocol.

When possible, Nessus tracks errors or failures related to otherwise
valid credentials in order to highlight issues that may result in
incomplete scan results or limited scan coverage. The types of issues
that are tracked include errors that indicate that the account used
for scanning did not have sufficient permissions for a particular
check, intermittent protocol failures which are unexpected after the
protocol has been negotiated successfully earlier in the scan, and
intermittent authentication failures which are unexpected after a
credential set has been accepted as valid earlier in the scan. This
plugin reports when none of the above issues have been logged during
the course of the scan for at least one authenticated protocol. See
plugin output for details, including protocol, port, and account.

Please note the following :

- This plugin reports per protocol, so it is possible for
  issues to be encountered for one protocol and not another.
  For example, authentication to the SSH service on the
  remote target may have consistently succeeded with no
  privilege errors encountered, while connections to the SMB
  service on the remote target may have failed
  intermittently.

- Resolving logged issues for all available authentication
  protocols may improve scan coverage, but the value of
  resolving each issue for a particular protocol may vary
  from target to target depending upon what data (if any) is
  gathered from the target via that protocol and what
  particular check failed. For example, consistently
  successful checks via SSH are more critical for Linux
  targets than for Windows targets, and likewise
  consistently successful checks via SMB are more critical
  for Windows targets than for Linux targets.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/24");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  # No dependencies, since this is an ACT_END plugin
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("spad_log_func.inc");
include("cred_func.inc");
include("lcx.inc");

global_var auth_ok_count = 0;

function report_success(prefix, proto, db, port, user)
{
  if (lcx::check_localhost() && (proto == "SMB" || proto == "SSH"))
    return 0;

  local_var kb_prefix = prefix + proto + "/" + port;
  local_var report = '';

  auth_ok_count++;
  if (get_kb_list(kb_prefix + "/Failure")) return 0;
  if (proto == 'SSH' && lcx::has_ssh_priv_failures()) return 0;
  if (get_kb_list(kb_prefix + "*/Problem")) return 0;

  report += get_credential_description(proto:proto, port:port);

  report = '\nNessus was able to log into the remote host with no privilege or access' +
           '\nproblems via the following :\n\n' + report;

  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);

  return 1;
}

function report_localhost()
{
  if (!lcx::check_localhost()) return 0;
  if (!get_kb_item("Host/local_checks_enabled")) return 0;
  local_var host_level_proto = get_kb_item("HostLevelChecks/proto");
  if (empty_or_null(host_level_proto) || host_level_proto != "local") return 0;

  local_var report = 'Nessus was able to execute commands locally with sufficient privileges\n' +
                     'for all planned checks.\n\n'; 

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
  if (auth_ok_count > 0)
    exit(0, "Authentication successes encountered privilege, access, or intermittent failure issues.");
  else if (lcx::svc_available())
    exit(0, "No authentication successes using user supplied credentials to report.");
  else exit(0, "No local checks ports or services were detected.");
}
