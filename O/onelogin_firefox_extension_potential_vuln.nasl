#%NASL_MIN_LEVEL 999999

#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 7/18/2018

include("compat.inc");

if (description)
{
  script_id(100958);
  script_version("1.4");
  script_cvs_date("Date: 2018/07/20  0:18:55");

  script_name(english:"OneLogin Extension for Firefox Installed (deprecated)");
  script_summary(english:"Checks for the OneLogin Firefox extension.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"OneLogin, a password manager extension for the Firefox browser, is
installed on the remote Windows host.

Note that the OneLogin servers were compromised on May 31, 2017. It is
strongly recommended that users change their OneLogin password and the
passwords for all accounts that were stored in OneLogin

Note that OneLogin has corrected the issue and taken measures
to ensure their data integrity moving forward so this plugin
has been deprecated.");
  script_set_attribute(attribute:"see_also", value:"https://www.onelogin.com");
  # http://www.zdnet.com/article/onelogin-hit-by-data-breached-exposing-sensitive-customer-data/?loc=newsletter_large_thumb_related&ftag=TREc64629f&bhid=21732286245179800775652060186740
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0714cb16");
  script_set_attribute(attribute:"see_also", value:"https://www.onelogin.com/blog/may-31-2017-security-incident");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:onelogin:onelogin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("win_firefox_browser_addons.nbin");
  script_require_keys("Browser/Firefox/Extension", "Mozilla/Firefox/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("smb_hotfixes_fcheck.inc");
include("browser.inc");

exit(0, "This plugin has been deprecated.");

get_kb_item_or_exit("Mozilla/Firefox/Version");

ffe = "OneLogin Firefox extension";

installs = get_browser_addons(browser:"Firefox", type:"Extension", name:"OneLogin for Firefox");
installs = installs['addons'];

if (max_index(installs) == 0)
  audit(AUDIT_NOT_INST, ffe);

# branch on detected installs to stay sane
install      = branch(installs);
install_path = install['path'];
version      = install['version'];

port = get_kb_item('SMB/transport');
if (!port)
  port = 445;

order = make_list("Extension path", "Extension version");
report = make_array(
  order[0], install_path,
  order[1], version
);
report = report_items_str(report_items:report, ordered_fields:order);
security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
