#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101817);
  script_version("1.4");
  script_cvs_date("Date: 2018/07/06 11:26:08");

  script_cve_id("CVE-2017-6753");
  script_bugtraq_id(99614);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170717-webex");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf15012");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf15020");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf15030");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf15033");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf15036");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf15037");
  script_xref(name:"IAVA", value:"2017-A-0216");

  script_name(english:"Cisco WebEx Extension for Firefox < 1.0.12 'atgpcext' Library GPC Sanitization RCE (cisco-sa-20170717-webex)");
  script_summary(english:"Checks the extension version.");

  script_set_attribute(attribute:"synopsis", value:
"A browser extension installed on the remote host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco WebEx Extension for Firefox installed on the remote host is
a version prior to 1.0.12. It is, therefore, affected by a remote code
execution vulnerability in the 'atgpcext' library due to incomplete
GPC sanitization. An unauthenticated, remote attacker can exploit
this, by convincing a user to visit a specially crafted website, to
execute arbitrary code with the privileges of the affected browser.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170717-webex
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a976aaa");
  script_set_attribute(attribute:"see_also", value:"https://thehackernews.com/2017/07/cisco-webex-vulnerability.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco WebEx Extension for Firefox version 1.0.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("win_firefox_browser_addons.nbin");
  script_require_keys("installed_sw/Mozilla Firefox", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("browser.inc");
include("misc_func.inc");
include("global_settings.inc");

get_kb_item_or_exit("installed_sw/Mozilla Firefox");

addons = get_browser_addons(browser:"Firefox", type:"all", name:"Cisco WebEx Extension", exit_on_fail:TRUE);
ext_report = "";
report = "";
ver = NULL;
ext = FALSE;
plg = FALSE;
vuln = 0;
paths = make_array();

fix = "1.0.12";

foreach addon(addons["addons"])
{
  ver_report = "";

  if(paths[addon['path']]) continue;

  ver_report += '\n  Extension name : ' + addon['name'] +
                '\n  Version        : ' + addon['version'];
  ver = chomp(addon['version']);

  if(empty_or_null(ver)) continue;

  if(ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
  {
    vuln += 1;
    ext_report += '\n' +
                  '\n  User           : ' + addon['user'] +
                  ver_report +
                  '\n  Update date    : ' + addon['update_date'] +
                  '\n  Path           : ' + addon['path'] +
                  '\n';
    paths[addon['path']] = TRUE;
  }
}

if(vuln)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if(vuln > 1) user = "users have";
  else user = "user has";

  report += '\n' +
            "The following " + user + " a vulnerable version of the Cisco WebEx Extension for Firefox installed :" +
            ext_report +
            '\n' +
            "Fix : Upgrade to Cisco WebEx Extension version 1.0.12 or later." +
            '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco WebEx Extension for Firefox");
