#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(161695);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/31");

  script_cve_id("CVE-2017-7529");
  script_bugtraq_id(103938);

  script_name(english:"Nginx Plus > R13 Data Disclosure Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a data disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to it's self reported version, the installed version of Nginx Plus is prior to R13 (built on Open Source 
version 1.13.4). It is, therefore, affected by an integer overflow vulnerability in the range filter module. An 
unauthenticated, remote attacker can exploit this, via a specially crafted request to disclose potentially sensitive 
information.");
  script_set_attribute(attribute:"see_also", value:"https://docs.nginx.com/nginx/releases/");
  script_set_attribute(attribute:"see_also", value:"https://nginx.org/en/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/security_advisories.html");
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2017/000200.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade tp Nginx Plus R13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7529");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nginx:nginx");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nginx_nix_installed.nbin");
  script_require_keys("installed_sw/Nginx Plus");

  exit(0);
}

include('vcf_extras_nginx.inc');

appname = 'Nginx Plus';
get_install_count(app_name:appname, exit_if_zero:TRUE);
app_info = vcf::nginx_plus::combined_get_app_info(app:appname);

vcf::check_granularity(app_info:app_info, sig_segments:2);


constraints = [
  {'fixed_version' : '13.0','fixed_display' : 'R13'}
];

vcf::nginx_plus::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
