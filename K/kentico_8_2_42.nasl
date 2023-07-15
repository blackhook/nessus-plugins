#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141211);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id("CVE-2015-7822", "CVE-2015-7823");

  script_name(english:"Kentico CMS < 8.2.42 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web content management system on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Kentico CMS on the remote host is prior to 8.2.42. It is,
therefore, affected by multiple vulnerabilities :

  - Multiple cross-site scripting (XSS) vulnerabilities exist in the UIPage.aspx parameter name and the
    CMSBodyClass cookie variable due to improper validation of user-supplied input before returning it to
    users. An authenticated, remote attacker can exploit this, by convincing a user to click a
    specially crafted URL, to execute arbitrary script code in a user's browser session. (CVE-2015-7822)

  - An open redirect vulnerability exists in CMSPages/GetDocLink.ashx due to not validadating URL parameters.
    An unauthenticated, remote attacker can exploit this, by convincing a user to click on a specially-crafted
    URL with a link in the 'link' parameter, to redirect a user to the specified URL. (CVE-2015-7823)

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  # https://packetstormsecurity.com/files/133981/Kentico-CMS-8.2-Cross-Site-Scripting-Open-Redirect.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24e7f308");
  script_set_attribute(attribute:"see_also", value:"https://devnet.kentico.com/download/hotfixes");
  script_set_attribute(attribute:"solution", value:
"Apply the hotfix applicable to your current version or upgrade to the latest available stable version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7823");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kentico:kentico_cms");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kentico_cms_win_installed.nbin");
  script_require_keys("installed_sw/Kentico CMS");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Kentico CMS');

constraints = [
  { 'fixed_version' : '8.2.5767.3968', 'fixed_display' : '8.2.5767.3968 (Hotfix 8.2.42)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, flags:{xss:TRUE}, severity:SECURITY_WARNING);
