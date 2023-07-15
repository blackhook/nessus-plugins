##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161976);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/13");

  script_cve_id("CVE-2022-24522");

  script_name(english:"Skype Extension for Chrome < 10.2.0.9951 Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"A browser extension installed on the remote host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Skype Extension for Chrome installed on the remote host is a version prior to 10.2.0.9951. It is, therefore,
affected by an information disclosure vulnerability. An unauthenticated, remote attacker can exploit this, to expose
potentially sensitive information.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-24522");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Skype Extension for Chrome version 10.2.0.9951 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24522");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:skype_extension");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("win_chrome_browser_addons.nbin");
  script_require_keys("installed_sw/Google Chrome", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_reg_query.inc');
include('smb_hotfixes_fcheck.inc');
include('browser.inc');
include('json.inc');

get_kb_item_or_exit('installed_sw/Google Chrome');
get_kb_item_or_exit('SMB/WindowsVersion');

var addons = get_browser_addons(browser:'Chrome', type:'all', name:'Skype', exit_on_fail:TRUE);
var ext_report = '';
var report = '';
var vuln = 0;
var users = make_array();

hotfix_check_fversion_init();

foreach var addon (addons['addons'])
{
  if(users[addon['user']]) continue;

  # Try to get active version from preferences
  var path = pregmatch(pattern:"(.*)Extensions.*", string:addon['path']);
  path = path[1] + 'Secure Preferences';
  var prefs = hotfix_get_file_contents(path:path);
  var ver;

  if(prefs['error'] == 0)
  {
    prefs = json_read(prefs['data']);
    ver = prefs[0]['extensions']['settings']['lifbcibllhkdhoafpjfnlhfpfgnpldfl']['manifest']['version'];
    users[addon['user']] = TRUE;
  }

  if(empty_or_null(ver))
  {
    if (report_paranoia < 2)
    {
      hotfix_check_fversion_end();
      audit(AUDIT_PARANOID);
    }
    ver = chomp(addon['version']);
  }

  if(ver_compare(ver:ver, fix:'10.2.0.9951', strict:FALSE) < 0)
  {
    vuln += 1;
    ext_report += '\n' +
                  '\n  User        : ' + addon['user'] +
                  '\n  Version     : ' + ver +
                  '\n  Update date : ' + addon['update_date'] +
                  '\n  Path        : ' + addon['path'] +
                  '\n';
  }
}

hotfix_check_fversion_end();

if(vuln)
{
  var port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  var user;
  if(vuln > 1) user = 'users have';
  else user = 'user has';

  report += '\n' +
            'The following ' + user + ' a vulnerable version of the Skype Extension for Chrome installed :' +
            ext_report +
            '\n' +
            'Fix : Upgrade to Skype extension version 10.2.0.9951 or later.' +
            '\n';
  security_report_v4(severity:SECURITY_NOTE, port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Skype Extension for Chrome');
