#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119725);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id("CVE-2018-1172");

  script_name(english:"Squid 3.1.12.2 <= 3.1.x <= 3.1.23 / 3.2.0.8 <= 3.2.x <= 3.2.14 / 3.3.x / 3.4.x / 3.5.x <= 3.5.27 / 4.x < 4.0.13 Denial of Service Vulnerability (SQUID-2018:3)");
  script_summary(english:"Checks the version of Squid.");

  script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Squid running on the remote
host is 3.1.x after or equal to 3.1.12.2 and prior or equal to
3.1.23, 3.2.x after or equal to 3.2.0.8 and prior or equal to
3.2.0.8, 3.3.x, 3.4.x, 3.5.x prior or equal to 3.5.27, or 4.x prior
to 4.0.13. It is, therefore, affected by a denial of service (DoS)
vulnerability in the ESI response processing component due to
incorrect pointer handling. A remote attacker controlled server can
exploit this issue, via a crafted ESI response, to cause a denial of
service for all clients accessing the Squid service.

Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2018_3.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Squid version 4.0.13 or later. Alternatively, apply the
vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1172");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("squid_version.nasl");
  script_require_keys("installed_sw/Squid", "Settings/ParanoidReport");
  script_require_ports("Services/http_proxy", 3128, 8080);

  exit(0);
}

include("vcf.inc");
include("http.inc");

app = "Squid";
get_install_count(app_name:app, exit_if_zero:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:3128);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

# Affected versions:  Squid 3.1.12.2 -> 3.1.23
#                     Squid 3.2.0.8 -> 3.2.14
#                     Squid 3.3 -> 3.5.27
#                     Squid 4.x -> 4.0.12
# Fixed in version:   Squid 4.0.13
constraints = [
  {"min_version":"3.1.12.2", "max_version":"3.1.23", "fixed_version":"4.0.13"},
  {"min_version":"3.2.0.8", "max_version":"3.2.14", "fixed_version":"4.0.13"},
  {"min_version":"3.3", "max_version":"3.5.27", "fixed_version":"4.0.13"},
  {"min_version":"4.0", "fixed_version":"4.0.13"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
