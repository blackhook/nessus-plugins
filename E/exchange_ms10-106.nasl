#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(108801);
  script_version("1.4");
  script_cvs_date("Date: 2018/11/15 20:50:26");

  script_cve_id("CVE-2010-3937");
  script_bugtraq_id(45297);
  script_xref(name:"MSFT", value:"MS10-106");
  script_xref(name:"MSKB", value:"2407132");

  script_name(english:"MS10-106: Microsoft Exchange Server Denial of Service (uncredentialed)");
  script_summary(english:"Checks the version of Exchange");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Exchange 2007 running on the remote host is
affected by a denial of service vulnerability.  The Exchange service
does not process specially crafted RPC calls correctly, resulting in
an infinite loop.

A remote, authenticated attacker could exploit this by making a
specially crafted RPC call, causing the service to become
non-responsive.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2010/ms10-106");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Microsoft Exchange 2007 SP2 for x64
systems.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");

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
  {"min_version" : "8.2.0", "fixed_version":"8.2.305.3"},
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
