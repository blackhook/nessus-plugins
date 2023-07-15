#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139873);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2020-5767", "CVE-2020-5768");

  script_name(english:"WordPress Plugin 'Email Subscribers & Newsletters' Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote WordPress application has a plugin installed that is vulnerable to multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The WordPress application running on the remote host has a version of the 'Email Subscribers & Newsletters' plugin that
is affected by multiple vulnerabilities.

  - A cross-site request forgery (CSRF) vulnerability exists in the send_test_email component. An
    unauthenticated, remote attacker can exploit this, by tricking a user into visiting a specially crafted
    web page, to send forged emails. (CVE-2020-5767)

  - A blind SQL injection vulnerability exists in the es_newsletters_settings_callback component due to
    improper sanitization of user supplied input. An authenticated, remote attacker can exploit this issue via
    a specially crafted request to disclose potentially sensitive information. (CVE-2020-5768)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://wpvulndb.com/vulnerabilities/10321");
  script_set_attribute(attribute:"see_also", value:"https://wpvulndb.com/vulnerabilities/10322");
  script_set_attribute(attribute:"solution", value:
"Update the 'Email Subscribers & Newsletters' plugin to version 4.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5767");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_plugin_detect.nbin");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::wordpress::plugin::get_app_info(plugin:'email-subscribers');
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'fixed_version' : '4.5.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

