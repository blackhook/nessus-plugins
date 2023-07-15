#
# (C) Tenable Network Security, Inc.
#

include ("compat.inc");

if (description)
{
  script_id(110643);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-6336");

  script_name(english:"Facebook OSQuery Code Signing Bypass (macOS)");
  script_summary(english:"Gets the Facebook OSQuery version from from osqueryi --version command.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Facebook OSQuery on the remote host is affected by a code signing bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of Facebook OSQuery is less than 3.2.7 and is 
therefore vulnerable to allowing execution of malicious binaries due 
to accepting forged Apple signatures.");
  # https://www.okta.com/security-blog/2018/06/issues-around-third-party-apple-code-signing-checks/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e9d177b");
  script_set_attribute(attribute:"see_also", value:"https://github.com/facebook/osquery/releases/tag/3.2.7");
  script_set_attribute(attribute:"see_also", value:"https://github.com/facebook/osquery");
  script_set_attribute(attribute:"solution", value:
"Update Facebook OSQuery to version 3.2.7 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6336");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:facebook:osquery");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_facebook_osquery_installed.nbin");
  script_require_keys("installed_sw/OSQuery");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'OSQuery';

get_install_count(app_name:app, exit_if_zero:TRUE);
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
fix_ver = "3.2.7";
version = install['version'];
if (ver_compare(ver: version, fix: fix_ver) < 0)
{
  report =
    '\n  Path              : ' + install['path'] +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix_ver +
    '\n';

  security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
  exit(0);
}

audit(AUDIT_INST_VER_NOT_VULN, app, version);