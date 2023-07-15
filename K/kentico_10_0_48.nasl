#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137747);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/07");

  script_cve_id("CVE-2017-17736");

  script_name(english:"Kentico CMS 9.x < 9.0.51 / 10.x < 10.0.48 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"Kentico CMS is affected by a Privilege Escalation Vulnerability");
  script_set_attribute(attribute:"description", value:
"A privilege escalation vulnerability exists in Kentico 9.0 before 9.0.51 and 10.0 before 10.0.48. An unauthenticated,
remote attacker can exploit this, by visiting CMSInstall/install.aspx and then navigating to the CMS Administration
Dashboard, to gain administrative access to the CMS.");
  # https://blog.hivint.com/advisory-access-control-bypass-in-kentico-cms-cve-2017-17736-49e1e43ae55b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c4e7ec8");
  script_set_attribute(attribute:"solution", value:
"Apply the hotfix applicable to your current version or upgrade to the latest available stable version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-17736");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/23");

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
  { 'min_version' : '9.0', 'fixed_version' : '9.0.6173.26016', 'fixed_display' : '9.0.6173.26016 (Hotfix 9.0.51)' },
  { 'min_version' : '10.0', 'fixed_version' : '10.0.6558.30634', 'fixed_display' : '10.0.6558.30634 (Hotfix 10.0.48)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
