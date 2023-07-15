#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77246);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-3556");
  script_bugtraq_id(69111);

  script_name(english:"nginx < 1.6.1 / 1.7.4 SMTP STARTTLS Command Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a command injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version in the server response header,
the version of nginx installed on the remote host is 1.5.6 or higher,
1.6.x prior to 1.6.1, or 1.7.x prior to 1.7.4. It is, therefore,
affected by a command injection vulnerability.

A flaw exists in the function 'ngx_mail_smtp_starttls' within the file
'src/mail/ngx_mail_smtp_handler.c' whereby input to the STARTTLS
command is not properly sanitized. This could allow a remote attacker
in a privileged network position to obtain sensitive information by
injecting commands into an SSL session.

Note that this issue is exploitable only when nginx is used as an SMTP
proxy.");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/security_advisories.html");
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2014/000144.html");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/download/patch.2014.starttls.txt");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/CHANGES-1.6");
  script_set_attribute(attribute:"solution", value:
"Apply the patch manually, or upgrade to nginx 1.6.1 / 1.7.4 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3556");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nginx:nginx");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nginx_detect.nasl", "nginx_nix_installed.nbin");
  script_require_keys("installed_sw/nginx");

  exit(0);
}

include('http.inc');
include('vcf.inc');

appname = 'nginx';
get_install_count(app_name:appname, exit_if_zero:TRUE);
app_info = vcf::combined_get_app_info(app:appname);

vcf::check_all_backporting(app_info:app_info);

vcf::check_granularity(app_info:app_info, sig_segments:3);
# If the detection is only remote, Detection Method won't be set, and we should require paranoia
if (empty_or_null(app_info['Detection Method']) && report_paranoia < 2)
  audit(AUDIT_PARANOID);

constraints = [
  {'min_version':'1.5.6', 'fixed_version':'1.6.1'},
  {'min_version':'1.7.0', 'fixed_version':'1.7.4'}
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
