#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(152743);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/23");

  script_name(english:"Unix Software Discovery Commands Not Available");
  script_summary(english:"Reports hosts with issues affecting the discovery of software.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to log in to the remote host using the provided
credentials, but encountered difficulty running commands used to find
unmanaged software.");
  script_set_attribute(attribute:"description", value:
"Nessus found problems running commands on the target host which are
used to find software that is not managed by the operating system.
Details of the issues encountered are reported by this plugin.

Failure to properly execute commands used to find and characterize
unmanaged software on the target host can lead to scans that do not
report known vulnerabilities.  There may be little in the scan
results of unmanaged software plugins to indicate the missing
availability of the source commands except audit trail messages.

Commands used to find unmanaged software installations might fail for
a variety of reasons, including:

   * Inadequate scan user permissions,
   * Failed privilege escalation,
   * Intermittent network disruption, or
   * Missing or corrupt executables on the target host.

Please address the issues reported here and redo the scan.
");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/23");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/unmanaged_commands_supported");

  # No dependencies, since this is an ACT_END plugin
  exit(0);
}

include("lcx.inc");

get_kb_item_or_exit("Host/unmanaged_commands_supported");

failures = get_kb_list("Host/unmanaged_software_checks/Failures/*");
if(empty_or_null(failures))
{
  if(!get_kb_item("Host/unmanaged_software_checks"))
    exit(1, "Software discovery checks were not enabled, but there were no failures.  This should not happen.");
  exit(0, "Unix software discovery checks are available on the target host.");
}

foreach var failkey(keys(failures))
{
  cmd = cmd64 = res = res64 = NULL;
  cmd64 = failkey - 'Host/unmanaged_software_checks/Failures/';

  #This probably won't happen, but we don't want to report it if it does.
  if(cmd64 == "<error encoding command>")
    continue;

  if(!isnull(cmd64))
    cmd = base64_decode(str:cmd64);

  if(isnull(cmd))
    continue;

  res64 = failures[failkey];
  if(res64 == "<none>")
      res = "<command returned no result>";
  else if(!isnull(res64))
    res = base64_decode(str:res64);

  var spaces = 28 - strlen(cmd);
  if(spaces < 0)
    spaces = 0;

  spaces = crap(data:' ', length: spaces);

  report += '\n  ' + cmd + spaces + ':';
  report += '\n    ' + res + '\n';
}

if(empty_or_null(report))
  exit(1, "Failed Unix software discovery commands were recorded, but errors prevented this plugin from reporting them.");

report = 'Failures in commands used to assess Unix software:\n' + report + '\n';

login_used = get_kb_item("HostLevelChecks/login");
proto_used = toupper(get_kb_item("HostLevelChecks/proto"));

if (!isnull(login_used)) report += '\nAccount  : ' + login_used;
if (!isnull(proto_used)) report += '\nProtocol : ' + proto_used;
report += '\n';

security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);

