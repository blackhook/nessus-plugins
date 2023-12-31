#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62625);
  script_version("1.4");
  script_cvs_date("Date: 2018/07/12 19:01:17");

  script_cve_id("CVE-2011-4220");
  script_bugtraq_id(49923);
  script_xref(name:"CERT", value:"275036");
  script_xref(name:"EDB-ID", value:"19391");

  script_name(english:"Investintech SlimPDF Reader < 1.0.1.12 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SlimPDF Reader");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application installed that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Investintech SlimPDF Reader that is
earlier than 1.0.1.12 and therefore reportedly affected by multiple,
unspecified vulnerabilities.  These vulnerabilities could allow an
attacker to cause a denial of service condition or execute arbitrary
code on the remote host by tricking a victim into opening a specially
crafted PDF document."
  );
  script_set_attribute(attribute:"solution", value:"Upgrade SlimPDF Reader to version 1.0.1.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:investintech:slimpdf_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");

  script_dependencies('investintech_slimpdf_reader_installed.nasl');
  script_require_keys('SMB/Investintech_SlimPDF_Reader/Installed');
  
  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

appname = 'Investintech SlimPDF Reader';
kb_base = "SMB/Investintech_SlimPDF_Reader/";
report = '';

get_kb_item_or_exit(kb_base + 'Installed');
  
num_installed = get_kb_item_or_exit(kb_base + 'NumInstalls');
not_vuln_ver_list = make_list();

for (install_num = 0; install_num < num_installed; install_num++)
{
  path = get_kb_item_or_exit(kb_base + install_num + '/Path');
  ver = get_kb_item_or_exit(kb_base + install_num + '/Version');

  fix = '1.0.1.12';
  if (ver_compare(ver:ver, fix:fix) == -1)
  {
    report += 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix + '\n';
  }
  else not_vuln_ver_list = make_list(not_vuln_ver_list, ver);
}

versions_not_vuln = '';
for (i=0; i<max_index(not_vuln_ver_list); i++)
{
  versions_not_vuln += ver;
  if (max_index(not_vuln_ver_list) > 1)
  {
    if (i+2 == max_index(not_vuln_ver_list))
      versions_not_vuln += ' and ';
    else if (max_index(not_vuln_ver_list) != 2)
      versions_not_vuln += ', ';
  }
}

if (report != '')
{
  if (report_verbosity > 0) security_hole(port:get_kb_item('SMB/transport'), extra:report);
  else security_hole(get_kb_item('SMB/transport'));
  exit(0);
}
else
{
  if (max_index(not_vuln_ver_list) > 1)
    msg = appname + ' versions ' + versions_not_vuln + ' are installed and not affected.';
  else
    msg = appname + ' version ' + versions_not_vuln + ' is installed and not affected.';
  exit(0, msg);
}
