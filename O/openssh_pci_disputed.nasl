#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159492);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id("CVE-2016-20012", "CVE-2020-15778", "CVE-2021-36368");

  script_name(english:"OpenSSH PCI Disputed Vulnerabilities.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote host is potentially affected by multiple
vulnerabilities.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15778");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_keys("Settings/PCI_DSS");
  script_require_ports("Services/ssh", 22);

  exit(0);
}


if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

# Ensure the port is open.
var port = get_service(svc:'ssh', exit_on_fail:TRUE);

# Get banner for service
var banner = get_kb_item_or_exit("SSH/banner/"+port);

if ('openssh' >!< tolower(banner)) audit(AUDIT_NOT_LISTEN, 'OpenSSH', port);

var match = pregmatch(string:tolower(banner), pattern:"openssh[-_]([0-9][-._0-9a-z]+)");

if (isnull(match)) audit(AUDIT_SERVICE_VER_FAIL, 'OpenSSH', port);

var version = match[1];

var items = make_array('Version source', banner,
                       'Installed version', version);

var order = make_list('Version source', 'Installed version');

var report = report_items_str(report_items:items, ordered_fields:order);

security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
