##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147662);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/02");

  script_cve_id("CVE-2021-28041");
  script_xref(name:"IAVA", value:"2021-A-0121-S");

  script_name(english:"OpenSSH 8.2 < 8.5");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by a double-free error.");
  script_set_attribute(attribute:"description", value:
"ssh-agent in OpenSSH 8.2 < 8.5 has a double free that may be relevant in a few less-common scenarios, such as
unconstrained agent-socket access on a legacy operating system, or the forwarding of an agent to an attacker-controlled
host.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.openwall.com/lists/oss-security/2021/03/03/1");
  script_set_attribute(attribute:"see_also", value:"https://www.openssh.com/txt/release-8.5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 8.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28041");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/ssh");

  exit(0);
}

include('backport.inc');

# Ensure the port is open.
var port = get_service(svc:'ssh', exit_on_fail:TRUE);

# Get banner for service.
var banner = get_kb_item_or_exit('SSH/banner/' + port);

var bp_banner = tolower(get_backport_banner(banner:banner));
if ('openssh' >!< bp_banner) audit(AUDIT_NOT_LISTEN, 'OpenSSH', port);
if (report_paranoia < 2) audit(AUDIT_PARANOID);
if (backported) audit(code:0, AUDIT_BACKPORT_SERVICE, port, 'OpenSSH');

# Check the version in the backported banner.
var match = pregmatch(string:bp_banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match)) audit(AUDIT_SERVICE_VER_FAIL, 'OpenSSH', port);
var version = match[1];

var fix = '8.5';
if ((version !~ "^8.[2-4]([^0-9]|$)")) audit(AUDIT_LISTEN_NOT_VULN, 'OpenSSH', port, version);

var items = make_array('Version source', banner,
                   'Installed version', version,
                   'Fixed version', fix);
var order = make_list('Version source', 'Installed version', 'Fixed version');
var report = report_items_str(report_items:items, ordered_fields:order);

security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
