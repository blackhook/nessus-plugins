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
  script_id(100957);
  script_version("1.4");
  script_cvs_date("Date: 2018/07/20  0:18:55");

  script_name(english:"OneLogin Extension for Chrome Installed (deprecated)");
  script_summary(english:"Checks for the OneLogin Chrome extension.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"OneLogin, a password manager extension for the Chrome browser, is
installed on the remote Windows host.

Note that the OneLogin servers were compromised on May 31, 2017. It is
strongly recommended that users change their OneLogin password and the
passwords for all accounts that were stored in OneLogin.

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

  script_dependencies("win_chrome_browser_addons.nbin");
  script_require_keys("installed_sw/Google Chrome", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("datetime.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_reg_query.inc");
include("smb_hotfixes_fcheck.inc");
include("browser.inc");
include("json.inc");
include("obj.inc");

exit(0, "This plugin has been deprecated.");

get_kb_item_or_exit("installed_sw/Google Chrome");
addons = get_browser_addons(browser:"Chrome", type:"all", name:"OneLogin for Google Chrome", exit_on_fail:TRUE);
ext_report = "";
report = "";
vuln = 0;
users = make_array();

hotfix_check_fversion_init();

foreach addon(addons["addons"])
{
  if (
    empty_or_null(addon['user']) ||
    empty_or_null(addon['version']) ||
    empty_or_null(addon['path'])
  ) continue;

  vuln += 1;
  ext_report += '\n' +
                '\n  User              : ' + addon['user'] +
                '\n  Extension version : ' + addon['version'] +
                '\n  Extension path    : ' + addon['path'] +
                '\n';
}

hotfix_check_fversion_end();

if(vuln)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if(vuln > 1) user = "users have";
  else user = "user has";

  report += '\n' +
            "The following " +
            user +
            " a version of the OneLogin Extension for Chrome installed:" +
            ext_report;
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_NOT_INST, "OneLogin Extension for Chrome");
