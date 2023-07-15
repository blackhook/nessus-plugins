#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141210);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id("CVE-2018-6842", "CVE-2018-6843");

  script_name(english:"Kentico CMS 10.x < 10.0.50 / 11.x < 11.0.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web content management system on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Kentico CMS on the remote host is 10.x prior to 10.0.50
or 11.x prior to 11.0.3. It is, therefore, affected by multiple vulnerabilities :

  - A cross-site scripting (XSS) vulnerability exists due to improper validation of user-supplied input before
    returning it to users. An authenticated, remote attacker can exploit this, by convincing a user to click a
    specially crafted URL, to execute arbitrary script code in a user's browser session. (CVE-2018-6842)

  - A SQL injection (SQLi) vulnerability exists in the administrative interface due to improper validation of
    user-supplied input. An unauthenticated, remote attacker can exploit this to inject or manipulate SQL
    queries in the back-end database, resulting in the disclosure or manipulation of arbitrary data.
    (CVE-2018-6843)

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://gist.github.com/zamous/c0afd7e21f3111de873c7bef6dcd9dd7");
  script_set_attribute(attribute:"see_also", value:"https://devnet.kentico.com/download/hotfixes");
  script_set_attribute(attribute:"solution", value:
"Apply the hotfix applicable to your current version or upgrade to the latest available stable version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6843");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/12");
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
  { 'min_version' : '10', 'fixed_version' : '10.0.6586.15639', 'fixed_display' : '10.0.6586.15639 (Hotfix 10.0.50)' },
  { 'min_version' : '11', 'fixed_version' : '11.0.6587.21066', 'fixed_display' : '11.0.6587.21066 (Hotfix 11.0.3)'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  flags:{xss:TRUE, sqli:TRUE},
  severity:SECURITY_WARNING);
