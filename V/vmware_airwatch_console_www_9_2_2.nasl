#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106584);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-4951");
  script_bugtraq_id(102849);

  script_name(english:"VMware AirWatch Console 9.1.x < 9.1.5 / 9.2.x < 9.2.2 XSRF");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the install of VMware
AirWatch Console running on the remote host is 9.1.x prior to
9.1.5 or 9.2.x prior to 9.2.2. It is, therefore, affected by
a user-input validation error that allows cross-site request
forgery (XSRF) attacks.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0006.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to AirWatch Console version 9.1.5, 9.2.2  or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4951");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:airwatch");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_airwatch_console_detect_www.nbin");
  script_require_keys("installed_sw/AirWatch Console");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("vcf.inc");
include("http.inc");

get_install_count(app_name:"AirWatch Console", exit_if_zero:TRUE);
port = get_http_port(default:443);

app_info = vcf::get_app_info(app:"AirWatch Console", port:port, webapp:TRUE);

constraints = [
  { "min_version":"9.1.0", "fixed_version":"9.1.5" },
  { "min_version":"9.2.0", "fixed_version":"9.2.2" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{"xsrf":TRUE});
