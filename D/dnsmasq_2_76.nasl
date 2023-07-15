#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106138);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2015-8899");
  script_bugtraq_id(91031);

  script_name(english:"dnsmasq < 2.76 Empty Address Denial of Service (CVE-2015-8899)");
  script_summary(english:"Checks the version of dnsmasq");

  script_set_attribute(attribute:"synopsis", value:
"The remote DNS / DHCP service is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of dnsmasq installed on the remote host is at least 2.73
and prior to 2.76, and thus, is affected by a denial of service
vulnerability when handling a reply that a given name is empty while
the A or AAAA record is defined locally and in a hosts file.");
  script_set_attribute(attribute:"see_also", value:"http://www.thekelleys.org.uk/dnsmasq/CHANGELOG");
  # http://lists.thekelleys.org.uk/pipermail/dnsmasq-discuss/2016q2/010479.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1481bb05");
  script_set_attribute(attribute:"solution", value:
"Upgrade to dnsmasq 2.76 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8899");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/14");
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

# vuln introduced in 2.73, fixed in 2.76
if (version =~ "^2\.7[345]($|[^0-9])")
{
  report = '\n' +
    '\n  Installed version : ' + display_version +
    '\n  Fixed version     : dnsmasq-2.76' +
    '\n';
  security_report_v4(port:53, proto:"udp", severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version, 'udp');
