#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(108808);
  script_version ("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/05");

  script_cve_id(
    "CVE-2008-1446",
    "CVE-2009-3555",
    "CVE-2010-1256",
    "CVE-2010-1899",
    "CVE-2010-2566",
    "CVE-2010-2730",
    "CVE-2010-2731"
  );
  script_bugtraq_id(
    31682,
    36935,
    40573,
    42246,
    41314,
    43138,
    43140
  );
  script_xref(name:"MSFT", value:"MS08-062");
  script_xref(name:"MSFT", value:"MS10-040");
  script_xref(name:"MSFT", value:"MS10-049");
  script_xref(name:"MSFT", value:"MS10-065");
  script_xref(name:"MSKB", value:"953155");
  script_xref(name:"MSKB", value:"2124261");
  script_xref(name:"MSKB", value:"2271195");
  script_xref(name:"MSKB", value:"2290570");
  script_xref(name:"MSKB", value:"982666");
  script_xref(name:"MSKB", value:"973917");
  script_xref(name:"MSKB", value:"980436");
  script_xref(name:"IAVA", value:"2010-A-0120-S");
  script_xref(name:"IAVB", value:"2010-B-0045-S");
  script_xref(name:"IAVB", value:"2008-B-0075-S");

  script_name(english:"Microsoft IIS 7.0 Vulnerabilities (uncredentialed) (PCI/DSS)");
  script_summary(english: "Checks the web server banner.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server may allow remote code execution.");
  script_set_attribute(attribute:"description", value:
"According to the HTTP server banner the remote server is
IIS 7.0. The server may be vulnerable to a number of
vulnerabilities including a couple of remote code execution
vulnerabilities.");
  script_set_attribute(attribute:"solution", value:
"Ensure the appropriate patches have been applied.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(189, 310);

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Web Servers");

  script_dependencies("http_version.nasl");
  script_require_keys("www/iis", "Settings/ParanoidReport", "Settings/PCI_DSS");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

if (!get_kb_item("Settings/PCI_DSS"))
{
  audit(AUDIT_PCI);
}

if (report_paranoia < 2)
{
  audit(AUDIT_PARANOID);
}

get_kb_item_or_exit("www/iis");

app = "Microsoft IIS";
port = get_http_port(default:80);
banner = get_http_banner(port:port);
if (empty_or_null(banner) || "Server: Microsoft-IIS" >!< banner)
{
  audit(AUDIT_NOT_DETECT, app, port);
}

if ("Server: Microsoft-IIS/7.0" >!< banner)
{
  audit(AUDIT_LISTEN_NOT_VULN, app, port);
}

security_report_v4(severity:SECURITY_HOLE, port:port);
exit(0);
