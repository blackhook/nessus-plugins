#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(40472);
 script_version("1.13");
 script_cvs_date("Date: 2019/06/12 10:19:33");

 script_name(english: "PCI DSS compliance : options settings");

 script_set_attribute(attribute:"synopsis", value:
"Reports options used in a PCI DSS compliance test." );
 script_set_attribute(attribute:"description", value:
"This plugin reports the values of a few important scan settings
if PCI DSS compliance checks are enabled.  These scan settings are
preset based on the scan template you have selected, but in some
cases may be overriden." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/08/03");
 script_set_attribute(attribute:"plugin_type", value:"settings");
 script_end_attributes();

 script_summary(english: "Modify global variables for PCI DSS");
 script_category(ACT_SETTINGS);	

 script_copyright(english:"This script is Copyright (C) 2009-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english: "Settings");

# Make sure we run after these ACT_SETTINGS scripts
 script_dependencies("web_app_test_settings.nasl", "global_settings.nasl");
 exit(0);
}

include("global_settings.inc");

opt = get_preference("PCI DSS compliance[checkbox]:Check for PCI-DSS compliance");

if ("no" >< opt || "yes" >!< opt) exit(0, "PCI DSS compliance checks are disabled");
set_kb_item(name: "Settings/PCI_DSS", value: TRUE);
set_kb_item(name: "Settings/test_all_accounts", value: TRUE);

opt = get_preference("PCI DSS internal scan[checkbox]:Perform local checks for PCI-DSS compliance");
policy_name = get_preference("@internal@policy_name");
if ("yes" >< opt || "Internal PCI" >< policy_name)
{
  set_kb_item(name: "Settings/PCI_DSS_local_checks", value: TRUE);
  report = 'A PCI Internal scan has been selected.  Local checks will be performed.\n\n';
}
else if("no" >< opt || ("PCI" >< policy_name && "External" >< policy_name))
{
  rm_kb_item(name: "Settings/PCI_DSS_local_checks");
  report = 'An External PCI scan has been selected.  Local checks will not be performed.\n\n';
}


# generic Web Application Tests are not required by PCI DSS yet.
report += 'These settings are required to test cross-site scripting and SQL injection flaws:\n';
enabled = 'disabled';
if (get_kb_item("Settings/enable_web_app_tests"))
  enabled = 'enabled';

report += 'Web applications tests are ' + enabled + '.\n';

enabled = 'enabled';
if (get_kb_item("Settings/disable_cgi_scanning"))
  enabled = 'disabled';

report += 'CGI scanning is ' + enabled + '.\n\n';

t = get_kb_item("Settings/HTTP/max_run_time");
report += 'The timeout for web application tests is ' + t + ' seconds.\n';

security_note(port: 0, extra: report);
