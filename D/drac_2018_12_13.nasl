#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119833);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-15774", "CVE-2018-15776");
  script_bugtraq_id(106233);
  script_xref(name:"IAVA", value:"2018-A-0412-S");

  script_name(english:"Dell iDRAC Products Multiple Vulnerabilities (December 2018)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running iDRAC7 or iDRAC8 with a firmware version
prior to 2.61.60.60, or iDRAC9 with a firmware version prior to
3.20.21.20, 3.21.24.22, 3.21.26.22 or 3.23.23.23 and is therefore
affected by the following vulnerabilities:

  - An elevation of privilege vulnerability exists in Redfish
    interface. An authenticated, attacker can exploit, via a
    permissions check flaw, to gain elevated privileges.
    (CVE-2018-15774)

  - A flaw exists in iDRAC7 / iDRAC8 due to improper handling of
    an error. A unauthenticated, remote attacker can exploit this
    to gain access to a u-boot shell. (CVE-2018-15776)");
  # https://www.dell.com/support/article/us/en/04/sln315190/dell-emc-idrac-multiple-vulnerabilities-cve-2018-15774-and-cve-2018-15776
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?751fcfbd");
  script_set_attribute(attribute:"solution", value:
"Update the remote host to iDRAC7/iDRAC8 firmware 2.61.60.60, or
iDRAC9 firmware 3.20.21.20, 3.21.24.22, 3.21.26.22, 3.23.23.23 or
higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15774");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:remote_access_card");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac7");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac8");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac9");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drac_detect.nasl");
  script_require_keys("installed_sw/iDRAC");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");
include("http.inc");

port = get_http_port(default:443, embedded:TRUE);

app_info = vcf::idrac::get_app_info(port:port);

constraints = [
  {"idrac":"7", "min_version":"1.0", "fixed_version":"2.61.60.60"},
  {"idrac":"8", "min_version":"1.0", "fixed_version":"2.61.60.60"},
  {"idrac":"9", "min_version":"1.0", "fixed_version":"3.20.21.20"},
  {"idrac":"9", "min_version":"3.21.00.00", "fixed_version":"3.21.24.22"},
  {"idrac":"9", "min_version":"3.21.25.00", "fixed_version":"3.21.26.22"},
  {"idrac":"9", "min_version":"3.22.00.00", "fixed_version":"3.23.23.23"}
];

vcf::idrac::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
