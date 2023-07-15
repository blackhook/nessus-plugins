#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108800);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/05");

  script_cve_id(
    "CVE-2010-0024",
    "CVE-2010-0025",
    "CVE-2010-1689",
    "CVE-2010-1690"
  );

  script_bugtraq_id(
    39308,
    39381,
    39908,
    39910
  );
  script_xref(name:"MSFT", value:"MS10-024");
  script_xref(name:"IAVB", value:"2010-B-0029-S");
  script_xref(name:"MSKB", value:"976323");
  script_xref(name:"MSKB", value:"976702");
  script_xref(name:"MSKB", value:"976703");
  script_xref(name:"MSKB", value:"981383");
  script_xref(name:"MSKB", value:"981401");
  script_xref(name:"MSKB", value:"981407");

  script_name(english:"MS10-024: Microsoft Exchange Denial of Service (uncredentialed)");
  script_summary(english:"Checks the version of Exchange");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Microsoft Exchange / Windows SMTP Service
is affected by at least one vulnerability :

  - Incorrect parsing of DNS Mail Exchanger (MX) resource
    records could cause the Windows Simple Mail Transfer
    Protocol (SMTP) component to stop responding until
    the service is restarted. (CVE-2010-0024)

  - Improper allocation of memory for interpreting SMTP
    command responses may allow an attacker to read random
    email message fragments stored on the affected server.
    (CVE-2010-0025)

  - Predictable transaction IDs are used, which could allow
    a man-in-the-middle attacker to spoof DNS responses.
    (CVE-2010-1689)

  - There is no verification that the transaction ID of a
    response matches the transaction ID of a query, which
    could allow a man-in-the-middle attacker to spoof DNS
    responses. (CVE-2010-1690)"
  );
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2010/ms10-024
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?261981ca");
  script_set_attribute(attribute:"solution",value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
and 2008 as well as Exchange Server 2000, 2003, 2007, and 2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("exchange_detect.nbin");
  script_require_keys("installed_sw/Exchange Server");
  script_require_ports("Services/smtp", 25, "Services/pop3", 143, "Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");

appname = 'Exchange Server';
get_install_count(app_name:appname, exit_if_zero:TRUE);

smtp_ports = get_kb_list("Services/smtp");
pop3_ports = get_kb_list("Services/pop3");
http_ports = get_kb_list("Services/www");

ports = make_list(smtp_ports, pop3_ports, http_ports);
port = branch(ports);
app_info = vcf::get_app_info(app:appname, port:port, service:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {"min_version" : "6.0.0", "fixed_version":"6.0.6620.15"},
  {"min_version" : "6.5.0", "fixed_version":"6.5.7656.2"},
  {"min_version" : "8.0.0", "fixed_version":"8.1.436.0"},
  {"min_version" : "8.2.0", "fixed_version":"8.2.254.0"},
  {"min_version" : "14.0.0","fixed_version":"14.0.694.0"}
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
