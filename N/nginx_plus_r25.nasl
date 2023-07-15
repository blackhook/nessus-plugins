#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(161698);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2021-23017");
  script_xref(name:"IAVB", value:"2021-B-0031");

  script_name(english:"Nginx Plus < R24 P1 1-Byte Memory Overwrite RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to it's self reported version, the installed version of Nginx Plus prior to R24 P1. It is, therefore, 
affected by a remote code execution vulnerability. A security issue in nginx resolver was identified, which might 
allow an unauthenticated remote attacker to cause 1-byte memory overwrite by using a specially crafted DNS response, 
resulting in worker process crash or, potentially, in arbitrary code execution.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://docs.nginx.com/nginx/releases/");
  script_set_attribute(attribute:"see_also", value:"https://nginx.org/en/security_advisories.html");
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2021/000300.html");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/download/patch.2021.resolver.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nginx Plus R25 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23017");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(193);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nginx:nginx");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nginx_nix_installed.nbin");
  script_require_keys("installed_sw/Nginx Plus");

  exit(0);
}

include('vcf_extras_nginx.inc');

var appname = 'Nginx Plus';
get_install_count(app_name:appname, exit_if_zero:TRUE);

var app_info = vcf::nginx_plus::combined_get_app_info(app:appname);

vcf::check_granularity(app_info:app_info, sig_segments:2);

# Vulnerable Open Source Versions: 0.6.18-1.20.0
# Fixed Open Source Version is 1.21.0
# Nginx Plus R24 is version 1.19.10
# Nginx Plus R25 is version 1.21.3 (first fixed version for Nginx Plus)
var constraints = [
  {'fixed_version' : '24.1', 'fixed_display': 'R24 P1 / R25' }
];

vcf::nginx_plus::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
