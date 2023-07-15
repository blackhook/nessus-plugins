#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108799);
  script_version("1.13");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2009-0098", "CVE-2009-0099");
  script_bugtraq_id(33134, 33136);
  script_xref(name:"MSFT", value:"MS09-003");
  script_xref(name:"MSKB", value:"959241");
  script_xref(name:"MSKB", value:"959897");

  script_name(english:"MS09-003: Microsoft Exchange Remote Code Execution (959239) (Uncredentialed)");
  script_summary(english:"Checks the version of Exchange");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the email
server.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Exchange that is
affected by a memory corruption vulnerability that could lead to
remote code execution when processing a specially crafted TNEF message
as well as a denial of service vulnerability when processing a
specially crafted MAPI command that could cause the Microsoft Exchange
System Attendant service and other services that use the EMSMDB32
provider to stop responding.");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2009/ms09-003
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20f7b688");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Exchange 2000, 2003, and
2007.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-0098");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {"min_version" : "6.0.0", "fixed_version":"6.0.6620.9"},
  {"min_version" : "6.5.0", "fixed_version":"6.5.7654.4"},
  {"min_version" : "8.0.0", "fixed_version":"8.1.340.1"} # do SP0 & SP1 combined
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
