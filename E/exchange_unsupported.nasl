#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(108802);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/27");

  script_xref(name:"IAVA", value:"0001-A-0554");

  script_name(english:"Microsoft Exchange Server Unsupported Version Detection (Uncredentialed)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server running on the remote host is no longer
supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Microsoft Exchange Server on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Microsoft Exchange Server that is currently
supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score for unsupported software");
  
  # https://support.microsoft.com/en-us/hub/4095338/microsoft-lifecycle-policy
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7ccf95d");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("exchange_detect.nbin");
  script_require_keys("installed_sw/Exchange Server");
  script_require_ports("Services/smtp", 25, "Services/pop3", 143, "Services/www", 80);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('install_func.inc');

# https://technet.microsoft.com/en-us/library/hh135098

var appname = 'Exchange Server';
get_install_count(app_name:appname, exit_if_zero:TRUE);

var smtp_ports = get_kb_list("Services/smtp");
var pop3_ports = get_kb_list("Services/pop3");
var http_ports = get_kb_list("Services/www");

var ports = make_list(smtp_ports, pop3_ports, http_ports);
var port = branch(ports);
var install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);

if (empty_or_null(install["major"]) || empty_or_null(install["minor"]))
{
  audit(AUDIT_VER_NOT_GRANULAR, appname, install["version"]);
}

var name = NULL;
if (install["major"] == "5")
{
  # so old. I don't think we need to go any further back
  name = '5';
}
else if (install["major"] == "6")
{
  if (install["minor"] == "0")
  {
    name = '2000';
  }
  else if (install["minor"] == "5")
  {
    name = '2003';
  }
}
else if (install["major"] == "8")
{
  if (install["minor"] == "0")
  {
    name = '2007';
  }
  else if (install["minor"] == "1")
  {
    name = '2007 SP1';
  }
  else if (install["minor"] == "2")
  {
    name = '2007 SP2';
  }
  else if (install["minor"] == "3")
  {
    name = '2007 SP3';
  }
}
else if (install["major"] == "14")
{
  if (install["minor"] == "0")
  {
    name = '2010';
  }
  else if (install["minor"] == "1")
  {
    name = '2010 SP1';
  }
  else if (install["minor"] == "2")
  {
    name = '2010 SP2';
  }
  else if (install["minor"] == "3")
  {
    name = '2010 SP3';
  }
}
else if (install["major"] == "15")
{
  if (install["minor"] == "0" && install['patch'] < 1497 )
  {
    name = '2013';
  }
  else if (install["minor"] == "1" && install['patch'] < 2507 )
  {
    name = '2016';
  }
  else if (install["minor"] == "2" && install['patch'] < 986 )
  {
    name = '2019';
  }
}

if (!isnull(name))
{
  register_unsupported_product(
    product_name:"Microsoft Exchange Server",
    cpe_base:"microsoft:exchange_server",
    version:install["version"]);

  var report = '\nThe remote host is running Microsoft Exchange Server:\n' +
           '\nname:    ' + name +
           '\nversion: ' + install["version"] +
           '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
  exit(0);
}
else
{
  audit(AUDIT_LISTEN_NOT_VULN, appname, port, install["version"]);
}
