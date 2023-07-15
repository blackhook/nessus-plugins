#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108380);
  script_version("1.5");
  script_cvs_date("Date: 2018/11/15 20:50:25");

  script_cve_id("CVE-2013-2619");
  script_bugtraq_id(58794);

  script_name(english:"Aspen < 0.22 Directory Traversal");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a directory traversal
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Aspen running on the remote
host is prior to 0.22. It is, therefore, affected by a directory
traversal vulnerability due to improper sanitization of user-supplied
input.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2013/Apr/2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Aspen version 0.22 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:aspen:aspen");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");

  script_dependencies("aspen_web_detect.nbin");
  script_require_keys("installed_sw/Aspen");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("vcf.inc");
include("http.inc");

app = "Aspen";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);
install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

kb_base = "www/aspen/"+port+"/";
app_info = vcf::get_app_info(
  app       : app,
  port      : port,
  kb_ver    : kb_base+"version",
  kb_source : kb_base+'source',
  service   : TRUE
);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "fixed_version" : "0.22" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
