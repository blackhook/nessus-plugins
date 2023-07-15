#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103647);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/08");

  script_cve_id(
    "CVE-2017-13704",
    "CVE-2017-14491",
    "CVE-2017-14492",
    "CVE-2017-14493",
    "CVE-2017-14494",
    "CVE-2017-14495",
    "CVE-2017-14496"
  );
  script_xref(name:"IAVA", value:"2017-A-0284-S");

  script_name(english:"dnsmasq < 2.78 Multiple Remote Vulnerabilities");
  script_summary(english:"Checks the version of dnsmasq");

  script_set_attribute(attribute:"synopsis", value:
"The remote DNS / DHCP service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of dnsmasq installed on the remote host is prior to 2.78,
and thus, is affected by the following vulnerabilities :

  - Denial of service related to handling DNS queries
    exceeding 512 bytes. (CVE-2017-13704)

  - Heap overflow related to handling DNS requests. (CVE-2017-14491)

  - Heap overflow related to IPv6 router advertisement handling.
    (CVE-2017-14492)

  - Stack overflow related to DHCPv6 request handling.
    (CVE-2017-14493)

  - Memory disclosure related to DHCPv6 packet handling.
    (CVE-2017-14494)

  - Denial of service related to handling DNS queries.
    (CVE-2017-14495)

  - Denial of service related to handling DNS queries.
    (CVE-2017-14496)");
  script_set_attribute(attribute:"see_also", value:"http://www.thekelleys.org.uk/dnsmasq/CHANGELOG");
  # https://security.googleblog.com/2017/10/behind-masq-yet-more-dns-and-dhcp.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1684fac7");
  # https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14491-asan.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2aa30bbb");
  # https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14491-instructions.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e408fdc");
  # https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14491.py
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3cd1c58");
  # https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14492-asan.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d610ee71");
  # https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14492-instructions.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90a10783");
  # https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14492.py
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32875869");
  # https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14493-asan.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfdf89ab");
  # https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14493-instructions.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8fac9ecd");
  # https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14493.py
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?460d9edd");
  # https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14494-instructions.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e88e5476");
  # https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14494.py
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e246b99");
  # https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14495-instructions.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dcbc583d");
  # https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14495.py
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?edfa62f7");
  # https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14496-asan.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8916059f");
  # https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14496-instructions.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7493663");
  # https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14496.py
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c356dcf1");
  # https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/sandbox/dnsmasq-sandbox.patch
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9bfb7dbc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to dnsmasq 2.78 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14493");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:thekelleys:dnsmasq");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dns_version.nasl");
  script_require_keys("dns_server/version", "Settings/ParanoidReport");
  script_require_ports("Services/dns", 53);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "dnsmasq";

port = get_kb_item("Services/udp/dns");
if (!port) port = 53;

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# dnsmasq replies to BIND.VERSION
version = get_kb_item_or_exit("dns_server/version");
version = tolower(version);
display_version = version;

if (version !~ "dnsmasq-(v)?")
  audit(AUDIT_NOT_LISTEN, app_name, port);

version = ereg_replace(pattern:"^dnsmasq-(v)?(.*)$", replace:"\2", string:version);

if (version == '2')
  audit(AUDIT_VER_NOT_GRANULAR, app_name, port, display_version);

if (version =~ "^([01]|2\.([0-9]|[0-6][0-9]|7[0-7]))($|[^0-9])")
{
  report = '\n' +
    '\n  Installed version : ' + display_version +
    '\n  Fixed version     : dnsmasq-2.78' +
    '\n';
  security_report_v4(port:53, proto:"udp", severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, display_version, 'udp');
