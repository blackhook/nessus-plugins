#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(40875);
  script_version("1.14");

  script_cve_id("CVE-2009-2957", "CVE-2009-2958");
  script_bugtraq_id(36120, 36121);

  script_name(english:"dnsmasq < 2.50 Multiple Remote TFTP Vulnerabilities");
  script_summary(english: "Checks the version of dnsmasq");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote TFTP service is affected by multiple vulnerabilities.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote host is running dnsmasq, a DNS and TFTP server. 

The version of dnsmasq installed on the remote host reports itself as
lower than 2.50.  Such versions include a TFTP server that is
reportedly affected by a number of issues:

  - A remote heap-overflow vulnerability exists because the
    software fails to properly bounds-check user-supplied 
    input before copying it into an insufficiently-sized 
    memory buffer. (CVE-2009-2957)

  - A malformed TFTP packet can crash dnsmasq with a NULL
    pointer dereference. (CVE-2009-2958)'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.coresecurity.com/content/dnsmasq-vulnerabilities'
  );
  script_set_attribute(
    attribute:'see_also',
    value:'https://seclists.org/fulldisclosure/2009/Aug/450'
  );
  # https://web.archive.org/web/20090901005927/http://www.thekelleys.org.uk/dnsmasq/CHANGELOG
  script_set_attribute(
    attribute:'see_also',
    value:'http://www.nessus.org/u?a0dc0215'
  );
   # http://lists.thekelleys.org.uk/pipermail/dnsmasq-discuss/2009q3/003253.html
  script_set_attribute(
    attribute:'see_also',
    value:'http://www.nessus.org/u?7052e1ae'
  );
  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to dnsmasq 2.50 or later.'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 399);

  script_set_attribute( attribute:'vuln_publication_date', value:'2009/08/31' );
  script_set_attribute( attribute:'patch_publication_date', value:'2009/08/31' );
  script_set_attribute( attribute:'plugin_publication_date', value:'2009/09/04' );

 script_cvs_date("Date: 2018/11/15 20:50:21");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:thekelleys:dnsmasq");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2018 Tenable Network Security, Inc.");
  script_family(english: "DNS");

  script_dependencie("dns_version.nasl", "tftpd_detect.nasl");
  script_require_keys("dns_server/version", "Settings/ParanoidReport");
  script_require_ports("Services/dns", 53, "Services/udp/tftp");
 
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "dnsmasq";

get_kb_item_or_exit("Services/udp/dns");
port = get_kb_item_or_exit( "Services/udp/tftp" );

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

if (version =~ "^([01]\.|2\.([0-9]|[1-4][0-9])$)")
{
  report = '\n' +
    '\n  Installed version : ' + display_version +
    '\n  Fixed version     : dnsmasq-2.50' +
    '\n';
  security_report_v4(port:port, proto:"udp", severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, display_version, 'udp');
