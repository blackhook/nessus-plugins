#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108809);
  script_version("1.4");
  script_cvs_date("Date: 2018/12/17 13:39:24");

  script_cve_id("CVE-2016-4554");

  script_name(english:"Squid < 3.5.18 Host Header Handling Same-Origin Protection / Content Filtering Bypass (SQUID-2016:8)");
  script_summary(english:"Checks the version of Squid.");

  script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is potentially affected by a same-origin
filtering bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Squid running on the remote
host is prior to 3.5.18. It is, therefore, potentially affected by
a Host header same-origin filtering bypass vulnerability. A remote
attacker could exploit this issue to poison the cache by forcing
a Host header value past same-origin security protections to cause
Squid to contact the wrong origin server.

Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.
Furthermore, the patch released to address this issue does not
update the version given in the banner. If the patch has been applied
properly, and the service has been restarted, then consider this to be
a false positive.");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2016_8.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Squid version 3.5.18 or later. Alternatively, apply
the vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4554");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

# Affected versions:  Squid 1.x -> 3.5.17
# Fixed in version:   Squid 3.5.18
constraints = [{ "min_version":"1.0", "fixed_version":"3.5.18" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
