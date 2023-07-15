#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111604);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2018-1212",
    "CVE-2018-1243",
    "CVE-2018-1244",
    "CVE-2018-1249"
  );
  script_bugtraq_id(104964, 104965);

  script_name(english:"Dell iDRAC Products Multiple Vulnerabilities (June 2018)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running iDRAC6 with a firmware version prior to
2.91, iDRAC7 or iDRAC8 with a firmware version prior to 2.60.60.60, or
iDRAC9 with a firmware version prior to 3.21.21.21 and is therefore
affected by multiple vulnerabilities.");
  # http://en.community.dell.com/techcenter/extras/m/white_papers/20487494
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6055fe8d");
  script_set_attribute(attribute:"solution", value:
"Update the remote host to iDRAC 6 firmware 2.91, iDRAC7/iDRAC8
firmware 2.60.60.60, or iDRAC9 firmware 3.21.21.21 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1244");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:remote_access_card");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac6");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac7");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac8");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac9");
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
  {"idrac":"6", "min_version":"1.0", "fixed_version":"2.91"},
  {"idrac":"7", "min_version":"1.0", "fixed_version":"2.60.60.60"},
  {"idrac":"8", "min_version":"1.0", "fixed_version":"2.60.60.60"},
  {"idrac":"9", "min_version":"1.0", "fixed_version":"3.21.21.21"}
];

vcf::idrac::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
