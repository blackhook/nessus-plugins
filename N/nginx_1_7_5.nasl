#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78386);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-3616");
  script_bugtraq_id(70025);

  script_name(english:"nginx < 1.6.2 / 1.7.5 SSL Session Reuse");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an SSL session handling
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version in the server response header,
the version of nginx installed on the remote host is 0.5.6 or higher,
1.6.x prior to 1.6.2, or 1.7.x prior to 1.7.5. It is, therefore,
affected by an SSL session or TLS session ticket key handling error. A
flaw exists in the file 'event/ngx_event_openssl.c' that could allow a
remote attacker to obtain sensitive information or to take control of
a session.

Note that this issue only affects servers having multiple 'server{}'
configurations sharing the same values for 'ssl_session_cache' or
'ssl_session_ticket_key'.");
  script_set_attribute(attribute:"see_also", value:"http://bh.ht.vc/vhost_confusion.pdf");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/security_advisories.html");
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2014/000146.html");
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2014/000145.html");
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2014/000147.html");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/CHANGES-1.6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to nginx 1.6.2 / 1.7.5 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"The NVD score does not account for the potential for the virtual host confusion attack being used to access confidential data (as detailed in the original Virtual Host Confusion: Weaknesses and Exploits Blackhat 2014 paper from Antoine Delignat-Lavaud)");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/13");

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
  {'min_version':'0.5.6', 'fixed_version':'1.6.2'},
  {'min_version':'1.7.0', 'fixed_version':'1.7.5'}
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
