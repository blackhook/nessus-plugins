#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141213);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id("CVE-2018-19453");

  script_name(english:"Kentico CMS < 11.0.45 Unrestricted Upload");

  script_set_attribute(attribute:"synopsis", value:
"A web content management system on the remote host is affected by an unrestricted upload flaw.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Kentico CMS on the remote host is prior to 11.0.45. It
is, therefore, affected by an unrestricted upload flaw. An unauthenticated, remote attacker can exploit this, by
uploading specially-crafted files with dangerous file types, to perform other attacks like cross-site scripting (XSS)
and cross-origin resource sharing (CORS).

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  # https://spz.io/2019/01/08/cve-2018-19453-upload-malicious-file-in-kentico-cms/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?774ad405");
  script_set_attribute(attribute:"see_also", value:"https://devnet.kentico.com/download/hotfixes");
  script_set_attribute(attribute:"solution", value:
"Update to Kentico CMS version 11.0.45 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19453");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/27");
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
  { 'fixed_version' : '11.0.6900.30678', 'fixed_display' : '11.0.6900.30678 (Hotfix 11.0.45)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
