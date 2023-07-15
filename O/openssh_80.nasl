#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159491);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2018-20685",
    "CVE-2019-6109",
    "CVE-2019-6110",
    "CVE-2019-6111"
  );

  script_name(english:"OpenSSH < 8.0");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote host is prior to 8.0. It is, therefore, affected
by the following vulnerabilities:

  - A permission bypass vulnerability due to improper directory name validation. An unauthenticated, remote
    attacker can exploit this, via with a specially crafted scp server, to change the permission of a directory
    on the client. (CVE-2018-20685)

  - Multiple arbitrary file downloads due to improper validation of object name and stderr output. An unauthenticated
    remote attacker can exploit this, via with a specially crafted scp server, to include additional hidden
    files in the transfer. (CVE-2019-6109, CVE-2019-6110)

  - An arbitrary file write vulnerability due to improper object name validation. An unauthenticated, remote
    attacker can exploit this, via with a specially crafted scp server, to overwrite arbitrary files in the
    client directory. (CVE-2019-6111)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://sintonen.fi/advisories/scp-client-multiple-vulnerabilities.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssh.com/txt/release-8.0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 8.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6111");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-6110");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var fix = '8.0';

if (ver_compare(ver:version, fix:fix) >=0)
  audit(AUDIT_LISTEN_NOT_VULN, 'OpenSSH', port, version);

var items = make_array('Version source', banner,
                   'Installed version', version,
                   'Fixed version', fix);

var order = make_list('Version source', 'Installed version', 'Fixed version');

var report = report_items_str(report_items:items, ordered_fields:order);

security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
