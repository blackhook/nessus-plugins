#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141212);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/22");

  script_cve_id("CVE-2019-19493");

  script_name(english:"Kentico CMS < 12.0.50 XSS");

  script_set_attribute(attribute:"synopsis", value:
"A web content management system on the remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Kentico CMS on the remote host is prior to 12.0.50. It
is, therefore, affected by a cross-site scripting (XSS) vulnerability due to the Content-Type header being inconsistent
with the file extension. An unauthenticated, remote attacker can exploit this, by convincing a user to click a specially
crafted URL, to execute arbitrary script code in a user's browser session.

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://devnet.kentico.com/download/hotfixes");
  script_set_attribute(attribute:"solution", value:
"Apply the hotfix applicable to your current version or upgrade to the latest available stable version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19493");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kentico:kentico_cms");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kentico_cms_win_installed.nbin");
  script_require_keys("installed_sw/Kentico CMS");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Kentico CMS');

constraints = [
  { 'fixed_version' : '12.0.7272.30705', 'fixed_display' : '12.0.7272.30705 (Hotfix 12.0.50)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, flags:{xss:TRUE}, severity:SECURITY_NOTE);
