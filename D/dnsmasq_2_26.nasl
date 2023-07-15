#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106137);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2008-3214");

  script_name(english:"dnsmasq 2.25 DHCP Request Denial of Service (CVE-2008-3214)");
  script_summary(english:"Checks the version of dnsmasq");

  script_set_attribute(attribute:"synopsis", value:
"The remote DNS / DHCP service is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of dnsmasq installed on the remote host is 2.25, and
thus, is affected by a denial of service vulnerability when
handling DHCP requests.");
  # http://lists.thekelleys.org.uk/pipermail/dnsmasq-discuss/2006q1/000579.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54ae9522");
  # http://thekelleys.org.uk/gitweb/?p=dnsmasq.git;a=blob_plain;f=CHANGELOG.archive;hb=HEAD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b18e6e8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to dnsmasq 2.26 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-3214");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:thekelleys:dnsmasq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

# only 2.25 is vuln
if (version =~ "^2\.25($|[^0-9])")
{
  report = '\n' +
    '\n  Installed version : ' + display_version +
    '\n  Fixed version     : dnsmasq-2.26' +
    '\n';
  security_report_v4(port:53, proto:"udp", severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version, 'udp');
