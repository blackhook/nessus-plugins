#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72835);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/05");

  script_cve_id("CVE-2009-0093", "CVE-2009-0233", "CVE-2009-0234");
  script_bugtraq_id(33982, 33988, 33989);
  script_xref(name:"MSFT", value:"MS09-008");
  script_xref(name:"IAVA", value:"2009-A-0018-S");
  script_xref(name:"MSKB", value:"961063");

  script_name(english:"MS09-008: Vulnerabilities in DNS Server Could Allow Spoofing (961063) (uncredentialed check)");
  script_summary(english:"Checks version of Microsoft DNS Server");

  script_set_attribute(attribute:"synopsis", value:
"The DNS server running on the remote host is vulnerable to DNS spoofing
attacks.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Microsoft DNS Server
running on the remote host has the following vulnerabilities :

  - An issue exists in installations where dynamic updates
    are enabled and ISATAP and WPAD are not already
    registered in DNS due to the lack of restricting
    registration on the 'wpad' hostname.  A remote,
    authenticated attacker can exploit this issue to
    perform a man-in-the-middle attack. (CVE-2009-0093)

  - An issue exists that allows a remote, unauthenticated
    attacker to quickly and reliably spoof responses and
    insert records into the DNS server's cache.
    (CVE-2009-0233)

  - An issue exists in the DNS Resolver Cache Service due
    to improper caching of DNS responses that could allow
    a remote, unauthenticated attacker to predict
    transaction IDs and poison caches by sending many
    crafted DNS queries. (CVE-2009-0234)

These issues may allow remote attackers to redirect network traffic
intended for systems on the Internet to the attacker's own systems.");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2009/ms09-008
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?c6b3fa4a");
  # https://blogs.technet.microsoft.com/srd/2009/03/13/ms09-008-dns-and-wins-server-security-update-in-more-detail/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8115046e");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, 2003 and
2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2014-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_dns_version.nasl");
  script_require_keys("ms_dns/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Settings/PCI_DSS") && report_paranoia < 2) audit(AUDIT_PARANOID);

version = get_kb_item_or_exit("ms_dns/version");
port = 53;
fix = NULL;

# Windows Server 2008
if (version =~ "^6\.0\.6001\.20\d{3}$" && ver_compare(ver:version, fix:"6.0.6001.22375") == -1)
  fix = "6.0.6001.22375";
else if (version =~ "^6\.0\.6001\.18\d{3}$" && ver_compare(ver:version, fix:"6.0.6001.18214") == -1)
  fix = "6.0.6001.18214";

# Windows Server 2003
else if (version =~ "^5\.2\.3790\.")
{
  # SP2
  if (
    ver_compare(ver:version, fix:"5.2.3790.3959") >= 0 &&
    ver_compare(ver:version, fix:"5.2.3790.4460") == -1
  )
    fix = "5.2.3790.4460";

  # SP1
  else if (ver_compare(ver:version, fix:"5.2.3790.3295") == -1)
    fix = "5.2.3790.3295";
  else
    audit(AUDIT_LISTEN_NOT_VULN, "Microsoft DNS Server", port, version, "UDP");
}

# Windows 2000
else if (version =~ "^5\.0\.2195\." && ver_compare(ver:version, fix:"5.0.2195.7260") == -1)
  fix = "5.0.2195.7260";

else
  audit(AUDIT_LISTEN_NOT_VULN, "Microsoft DNS Server", port, version, "UDP");


if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_warning(port:port, proto:"udp", extra:report);
}
else security_warning(port:port, proto:"udp");

