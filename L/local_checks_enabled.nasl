#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117887);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/12");

  script_xref(name:"IAVB", value:"0001-B-0516");

  script_name(english:"OS Security Patch Assessment Available");
  script_summary(english:"Reports hosts that have OS Security Patch Assessment available.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to log in to the remote host using the provided
credentials and enumerate OS security patch levels.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to determine OS security patch levels by logging
into the remote host and running commands to determine the version
of the operating system and its components.  The remote host was
identified as an operating system or device that Nessus supports for
patch and update assessment.  The necessary information was obtained
to perform these checks.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/02");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_ports("Host/local_checks_enabled", "SMB/MS_Bulletin_Checks/Possible");

  # No dependencies, since this is an ACT_END plugin
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_hotfixes.inc");
include("lcx.inc");

kb_enabled = get_kb_item("Host/local_checks_enabled");
ms_bulletin = get_kb_item("SMB/MS_Bulletin_Checks/Possible");
pm_checks = get_kb_item("Host/patch_management_checks");

# From scan_info.nasl
edge_case = !kb_enabled && ms_bulletin && !pm_checks;

if (!kb_enabled && !edge_case)
{
  if (lcx::svc_available()) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
  else exit(0, "No local checks ports or services were detected.");
}

report = 'OS Security Patch Assessment is available.\n';

# Windows local checks rely on more than "Host/local_checks_enabled"
# Check additional KB items

smb_local_checks = FALSE;
if (kb_enabled && !get_kb_item("SMB/not_windows") &&
    get_kb_item("Host/windows_local_checks"))
{
  login_used = get_kb_item("HostLevelChecks/smb_login");
  systemroot = hotfix_get_systemdrive(as_share:TRUE);

  if (ms_bulletin) smb_local_checks = TRUE;
  else if (get_kb_item("SMB/Registry/Enumerated") &&
           ( !isnull(systemroot) &&
             get_kb_item("SMB/AccessibleShare/"+systemroot) ))
    smb_local_checks = TRUE;
  else audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
}

replace_kb_item(name:"HostLevelChecks/local_security_checks_enabled",
  value:TRUE);

if (edge_case)
{
  login_used = get_kb_item("HostLevelChecks/login");
  smb_local_checks = TRUE;
}

if (smb_local_checks)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (!isnull(login_used))
    report += '\nAccount  : ' + login_used +
              '\nProtocol : SMB\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
  exit(0);
}

# Everything else

login_used = get_kb_item("HostLevelChecks/login");
proto_used = toupper(get_kb_item("HostLevelChecks/proto"));
if (isnull(proto_used))
{
  if (get_kb_item("Host/Cisco/IOS/Version"))
    proto_used = "SNMP";
  else if (get_kb_item("Host/Palo_Alto/Firewall/Source"))
    proto_used = "HTTPS";
  else
  {
    src = get_kb_item("Host/NetScaler/Source");
    if (src) proto_used = src;
  }
}

if (!isnull(login_used)) report += '\nAccount  : ' + login_used;
if (!isnull(proto_used)) report += '\nProtocol : ' + proto_used;
report += '\n';

security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
