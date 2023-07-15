#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130455);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2019-16905");
  script_xref(name:"IAVA", value:"2019-A-0400-S");

  script_name(english:"OpenSSH 7.7 < 8.1");
  script_summary(english:"Checks the OpenSSH banner version.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"OpenSSH 7.7 through 7.9 and 8.x before 8.1, when compiled with an experimental key type, has a pre-authentication
integer overflow if a client or server is configured to use a crafted XMSS key. This leads to memory corruption and
local code execution because of an error in the XMSS key parsing algorithm. NOTE: the XMSS implementation is
considered experimental in all released OpenSSH versions, and there is no supported way to enable it when building
portable OpenSSH.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.openwall.com/lists/oss-security/2019/10/09/1");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-8.1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 8.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16905");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/ssh");

  exit(0);
}

include('audit.inc');
include('backport.inc');
include('global_settings.inc');
include('misc_func.inc');

# Ensure the port is open.
port = get_service(svc:'ssh', exit_on_fail:TRUE);

# Get banner for service.
banner = get_kb_item_or_exit('SSH/banner/' + port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ('openssh' >!< bp_banner) audit(AUDIT_NOT_LISTEN, 'OpenSSH', port);
if (report_paranoia < 2) audit(AUDIT_PARANOID);
if (backported) audit(code:0, AUDIT_BACKPORT_SERVICE, port, 'OpenSSH');

# Check the version in the backported banner.
match = pregmatch(string:bp_banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match)) audit(AUDIT_SERVICE_VER_FAIL, 'OpenSSH', port);
version = match[1];

fix = '8.1';
if (!(version =~ "^7\.[7-9]" || version =~ "^8.0")) audit(AUDIT_LISTEN_NOT_VULN, 'OpenSSH', port, version);

items = make_array('Version source', banner,
                   'Installed version', version,
                   'Fixed version', fix);
order = make_list('Version source', 'Installed version', 'Fixed version');
report = report_items_str(report_items:items, ordered_fields:order);

security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
