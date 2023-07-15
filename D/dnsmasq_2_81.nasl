#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136411);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2019-14834");
  script_xref(name:"IAVA", value:"2020-A-0194-S");

  script_name(english:"dnsmasq < 2.81 Denial of Service (DoS) Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote DNS / DHCP service is affected by DoS vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of dnsmasq installed on the remote host is prior to 2.81. It is, therefore, affected by a denial of 
  service (DoS) vulnerability in 'helper.c' due to a memory leak. An unauthenticated, remote attacker can exploit this 
  issue, to cause the application to stop responding.

  Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
  number.");
  # http://thekelleys.org.uk/gitweb/?p=dnsmasq.git;a=commit;h=69bc94779c2f035a9fffdb5327a54c3aeca73ed5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19058d2f");
  script_set_attribute(attribute:"see_also", value:"http://www.thekelleys.org.uk/dnsmasq/CHANGELOG");
  script_set_attribute(attribute:"solution", value:
"Upgrade to dnsmasq 2.81 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14834");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:thekelleys:dnsmasq");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

fix = '2.81';
if (ver_compare(ver:version, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version, 'udp');

report = '\n' +
         '\n  Installed version : ' + display_version +
         '\n  Fixed version     : dnsmasq-' + fix +
         '\n';

security_report_v4(port:port, proto:"udp", severity:SECURITY_WARNING, extra:report);
