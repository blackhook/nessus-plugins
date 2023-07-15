#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(152742);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/23");

  script_name(english:"Unix Software Discovery Commands Available");
  script_summary(english:"Reports hosts that have all software discovery commands available.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to log in to the remote host using the provided
credentials and is able to execute all commands used to find
unmanaged software.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to determine that it is possible for plugins to find
and identify versions of software on the target host. Software that
is not managed by the operating system is typically found and
characterized using these commands.  This was measured by running
commands used by unmanaged software plugins and validating their
output against expected results.");
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

ums_available = get_kb_item("Host/unmanaged_software_checks");

if (!ums_available)
{
  if (lcx::svc_available())
    exit(0, "Unix software discovery commands failed.  Scan results for unmanaged software may be missing or incomplete.");
  else
    exit(0, "No local checks ports or services were detected.");
}

failures = get_kb_list("Host/unmanaged_software_checks/Failures/*");
if(!empty_or_null(failures))
  exit(1, "Error: Unix software checks were marked as available, but command failures occurred.");

report = 'Unix software discovery checks are available.\n';

login_used = get_kb_item("HostLevelChecks/login");
proto_used = toupper(get_kb_item("HostLevelChecks/proto"));

if (!isnull(login_used)) report += '\nAccount  : ' + login_used;
if (!isnull(proto_used)) report += '\nProtocol : ' + proto_used;
report += '\n';

security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
