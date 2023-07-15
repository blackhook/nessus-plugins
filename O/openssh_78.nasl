#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159490);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/17");

  script_cve_id("CVE-2018-15473");

  script_name(english:"OpenSSH < 7.8");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by a information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote host is prior to 7.8. It is, therefore, affected
by an information disclosure vulnerability in the auth2-gss.c, auth2-hostbased.c, and auth2-pubkey due to not delaying
for an invalid authenticating user. An unauthenticated, remote attacker can exploit this, via a malformed packet, to
potentially enumerate users.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.openwall.com/lists/oss-security/2018/08/15/5");
  script_set_attribute(attribute:"see_also", value:"https://www.openssh.com/txt/release-7.8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 7.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15473");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var fix = '7.8';

if (ver_compare(ver:version, fix:fix) >=0)
  audit(AUDIT_LISTEN_NOT_VULN, 'OpenSSH', port, version);

var items = make_array('Version source', banner,
                   'Installed version', version,
                   'Fixed version', fix);

var order = make_list('Version source', 'Installed version', 'Fixed version');

var report = report_items_str(report_items:items, ordered_fields:order);

security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
