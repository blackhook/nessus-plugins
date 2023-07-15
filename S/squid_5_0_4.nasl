#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139923);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-15810", "CVE-2020-15811");
  script_xref(name:"IAVB", value:"2020-B-0050-S");

  script_name(english:"Squid 2.x < 4.13 / 5.x < 5.0.4 (SQUID-2020:8 and SQUID-2020:10)");

  script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Squid running on the remote
host is 2.x prior to 4.13 or 5.x prior to 5.0.4.  It is,therefore,
affected by multiple vulnerabilities:

  - An input-validation flaw exists related to handling
    HTTP and HTTPS traffic that allows HTTP request
    splitting leading to cache poisoning. (CVE-2020-15810)

  - An input-validation flaw exists related to handling
    HTTP and HTTPS traffic that allows HTTP request
    smuggling leading to cache poisoning. (CVE-2020-15811)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://github.com/squid-cache/squid/security/advisories/GHSA-c7p8-xqhm-49wv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?109a5343");
  # https://github.com/squid-cache/squid/security/advisories/GHSA-3365-q9qx-f98m
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9a6f7c11");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Squid version 4.13 or 5.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15811");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("squid_version.nasl");
  script_require_keys("installed_sw/Squid", "Settings/ParanoidReport");
  script_require_ports("Services/http_proxy", 3128, 8080);

  exit(0);
}

include('http.inc');
include('vcf.inc');

get_install_count(app_name:'Squid', exit_if_zero:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

port = get_http_port(default:3128);

app_info = vcf::get_app_info(app:'Squid', port:port, webapp:TRUE);

constraints = [
  {'min_version':'2.0', 'fixed_version':'4.13'},
  {'min_version':'5.0', 'fixed_version':'5.0.4'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);


