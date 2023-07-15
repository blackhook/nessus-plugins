#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157842);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/14");

  script_cve_id(
    "CVE-2021-45951",
    "CVE-2021-45952",
    "CVE-2021-45953",
    "CVE-2021-45954",
    "CVE-2021-45955",
    "CVE-2021-45956",
    "CVE-2021-45957"
  );

  script_name(english:"dnsmasq 2.86 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote DNS / DHCP service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of dnsmasq installed on the remote host is 2.86. It is, therefore, affected by multiple
heap-based buffer overflow vulnerabilities in check_bad_address, dhcp_reply, extract_name, resize_packet,
print_mac and answer_request.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www.thekelleys.org.uk/dnsmasq/CHANGELOG");
  # https://github.com/google/oss-fuzz-vulns/blob/main/vulns/dnsmasq/OSV-2021-935.yaml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb603706");
  script_set_attribute(attribute:"solution", value:
"Upgrade to dnsmasq 2.87 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45957");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:thekelleys:dnsmasq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dns_version.nasl");
  script_require_keys("dns_server/version", "Settings/ParanoidReport");
  script_require_ports("Services/dns", 53);

  exit(0);
}

include('audit.inc');

app_name = 'dnsmasq';
port = get_kb_item('Services/udp/dns');

if (!port)
  port = 53;

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

# dnsmasq replies to BIND.VERSION
version = tolower(get_kb_item_or_exit('dns_server/version'));
display_version = version;

if (version !~ "dnsmasq-(v)?")
  audit(AUDIT_NOT_LISTEN, app_name, port);

version = preg_replace(pattern:"^dnsmasq-(v)?(.*)$", replace:"\2", string:version);

if (version == '2')
  audit(AUDIT_VER_NOT_GRANULAR, app_name, port, display_version);

var fix = '2.87';
var vuln = '2.86';
if (ver_compare(ver:version, minver: vuln, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version, 'udp');

report = '\n' +
         '\n  Installed version : ' + display_version +
         '\n  Fixed version     : dnsmasq-' + fix +
         '\n';

security_report_v4(port:port, proto:'udp', severity:SECURITY_HOLE, extra:report);
