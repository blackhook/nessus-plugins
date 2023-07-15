#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(17631);
 script_version("1.23");
 script_cvs_date("Date: 2018/11/15 20:50:21");
 script_cve_id("CVE-2005-0876", "CVE-2005-0877");
 script_bugtraq_id(12897);

 script_name(english:"dnsmasq < 2.21.0 Multiple Remote Vulnerabilities");
 script_summary(english:"Checks the version of dnsmasq");

 script_set_attribute(attribute:"synopsis", value:"The remote DNS / DHCP service is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host is running dnsmasq, a DHCP and DNS server.

The version of dnsmasq installed on the remote host contains an
off-by-one boundary error when reading a DHCP lease file. An attacker
can leverage this issue to cause the application to crash or possible
execute arbitrary code the next time it is restarted by sending a long
hostname and client-id when requesting a DHCP lease.

In addition, the application only checks the 16-bit ID against current
queries when receiving DNS replies. An attacker may be able to send a
flood of DNS replies and poison the DNS cache.");
 script_set_attribute(attribute:"see_also", value:"https://secuniaresearch.flexerasoftware.com/advisories/14691");
 script_set_attribute(attribute:"see_also", value:"http://www.thekelleys.org.uk/dnsmasq/CHANGELOG");
 script_set_attribute(attribute:"solution", value:"Upgrade to dnsmasq 2.21.0 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/25");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:thekelleys:dnsmasq");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2018 Tenable Network Security, Inc.");
 script_family(english:"DNS");

  script_dependencie("dns_version.nasl");
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

if (version =~ "^([01]\.|2\.([0-9]$|1[0-9]$|20))")
{
  report = '\n' +
    '\n  Installed version : ' + display_version +
    '\n  Fixed version     : dnsmasq-2.21' +
    '\n';
  security_report_v4(port:53, proto:"udp", severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, display_version, 'udp');
