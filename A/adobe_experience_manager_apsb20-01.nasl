##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143468);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id(
    "CVE-2019-16466",
    "CVE-2019-16467",
    "CVE-2019-16468",
    "CVE-2019-16469"
  );
  script_xref(name:"IAVB", value:"2020-B-0002-S");

  script_name(english:"Adobe Experience Manager 6.1 < 6.3.3.7 / 6.4 < 6.4.7.0 / 6.5 < 6.5.3.0 Multiple Vulnerabilities (APSB20-01)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Experience Manager installed on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Experience Manager installed on the remote host is 6.1.x less than 6.3.3.7, 6.4.x less than
6.4.7.0, or 6.5.x less than 6.5.4.0. It is, therefore, affected by multiple vulnerabilities that could lead to sensitive
information disclosure, as referenced in the APSB20-01 advisory, including the following:

  - A cross-site script inclusion vulnerability that allows remote attackers to disclose sensitive data via 
    unspecified means. (CVE-2019-16466)

  - A reflected cross-site script vulnerability due to improper validation of user-supplied input before
    returning it to users. An unauthenticated, remote attacker can exploit this, by convincing a user to click
    a specially crafted URL, to execute arbitrary script in a user's browser session. (CVE-2019-16467)

  - An expression language injection vulnerability due to improper sanitization of user supplied input that
    allows remote attackers to disclose sensitive information via unspecified means. (CVE-2018-16469)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/experience-manager/apsb20-01.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d873f10");
  script_set_attribute(attribute:"solution", value:
"Apply the recommended update from the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16469");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:experience_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_experience_manager_http_detect.nbin");
  script_require_keys("installed_sw/Adobe Experience Manager");

  exit(0);
}

include('vcf.inc');
include('http.inc');

port = get_http_port(default:4502);

app = 'Adobe Experience Manager';

# We may not get the version for 6.1 and 6.2, but we should get the Branch - if this is 6.1 or 6.2 we should flag
app_info = get_single_install(app_name:app, port:port, exit_if_unknown_ver:FALSE);

if (app_info['version'] == UNKNOWN_VER && app_info['Branch'] =~ "^6\.[12]($|[^0-9])")
  app_info['version'] = app_info['Branch'];
else if  (app_info['version'] == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_APP_VER, app);

app_info['parsed_version'] = vcf::parse_version(app_info['version']);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '6.1', 'fixed_version' : '6.3.3.7' },
  { 'min_version' : '6.4', 'fixed_version' : '6.4.7.0' },
  { 'min_version' : '6.5', 'fixed_version' : '6.5.3.0' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE}
);
