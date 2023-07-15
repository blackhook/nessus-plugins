#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119726);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id("CVE-2018-19131");

  script_name(english:"Squid 3.1.12.1 <= 3.1.x <= 3.1.23 / 3.2.0.4 <= 3.2.x / 3.3.x / 3.4.x / 3.5.x <= 3.5.28 / 4.x < 4.4 Cross-Site Scripting Vulnerability (SQUID-2018:4)");
  script_summary(english:"Checks the version of Squid.");

  script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Squid running on the remote
host is 3.1.x after or equal to 3.1.12.1 and prior or equal to
3.1.23, 3.2.x after or equal to 3.2.0.4, 3.3.x, 3.4.x, 3.5.x prior or
equal to 3.5.28, or 4.x prior to 4.4. It is, therefore, affected by a
cross-site scripting (XSS) vulnerability due to improper validation
of user-supplied input before returning it to users. A remote
attacker controlled server can exploit this, by triggering error page
delivery to a client with injected arbitrary script code that will
execute in the client's browser session.

Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2018_4.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Squid version 4.4 or later. Alternatively, apply the
vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19131");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/17");
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

# Affected versions:  Squid 3.1.12.1 -> 3.1.23
#                     Squid 3.2.0.4 -> 3.5.28
#                     Squid 4.0 -> 4.3
# Fixed in version:   Squid 4.4
constraints = [
  {"min_version":"3.1.12.1", "max_version":"3.1.23", "fixed_version":"4.4"},
  {"min_version":"3.2.0.4", "max_version":"3.5.28", "fixed_version":"4.4"},
  {"min_version":"4.0", "fixed_version":"4.4"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
