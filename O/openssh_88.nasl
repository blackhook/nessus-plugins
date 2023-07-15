#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154174);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/09");

  script_cve_id("CVE-2021-41617");
  script_xref(name:"IAVA", value:"2021-A-0474-S");

  script_name(english:"OpenSSH 6.2 < 8.8");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"sshd in OpenSSH 6.2 through 8.x before 8.8, when certain non-default configurations are used, allows privilege
escalation because supplemental groups are not initialized as expected. Helper programs for AuthorizedKeysCommand and
AuthorizedPrincipalsCommand may run with privileges associated with group memberships of the sshd process, if the
configuration specifies running the command as a different user.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.openwall.com/lists/oss-security/2021/09/26/1");
  script_set_attribute(attribute:"see_also", value:"https://www.openssh.com/txt/release-8.8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 8.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41617");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var minver = '6.2';
var fix = '8.8';
if (ver_compare(ver:version, minver:minver, fix:fix) >=0)
  audit(AUDIT_LISTEN_NOT_VULN, 'OpenSSH', port, version);

var items = make_array('Version source', banner,
                   'Installed version', version,
                   'Fixed version', fix);
var order = make_list('Version source', 'Installed version', 'Fixed version');
var report = report_items_str(report_items:items, ordered_fields:order);

security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
