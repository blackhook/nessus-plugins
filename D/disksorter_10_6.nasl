#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(110554);
  script_version("1.2");
  script_cvs_date("Date: 2018/06/18 11:51:45");
  script_xref(name:"EDB-ID", value:"40458");

  script_name(english:"Disk Sorter HTTP POST Request Handling Remote Stack Buffer Overflow");
  script_summary(english:"The remote host is affected by a buffer overflow vulnerability.");

  script_set_attribute(attribute:"synopsis",value:
  "The remote host is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description",value:"
  Disk Sorter product contains an overflow condition that is triggered
  when handling overly large HTTP POST requests e.g. sent to /login. 
  This may allow a remote attacker to cause a stack-based buffer 
  overflow and execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://disksorter.com");
  script_set_attribute(attribute:"solution", value:"Upgrade to Disk Sorter 10.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"cpe",value:"cpe:/a:flexense:disksorter");
  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("flexense_detect.nbin");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Disk Sorter");
  
  exit(0);
}

include("http.inc");
include("vcf.inc");

appname = 'Disk Sorter';

get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:80);

app_info = vcf::get_app_info(app:appname, port:port, webapp:TRUE);

constraints = [
  { "min_version" : "1.0.0", "max_version" : "10.5.0", "fixed_version" : "10.6.18" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);