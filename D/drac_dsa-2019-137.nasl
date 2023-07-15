#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131730);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-3764");

  script_name(english:"Dell iDRAC Improper Authorization (DSA-2019-137)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an improper authorization vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running iDRAC8 with a firmware version prior to 2.70.70.70 or iDRAC9 with a firmware version prior
to 3.36.36.36 and is therefore affected by an improper authorization vulnerability. A remote, authenticated iDRAC user
with low privileges can exploit this vulnerability to obtain sensitive information, such as password hashes.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/article/ie/en/iebsdt1/sln319317/dsa-2019-137-idrac-improper-authorization-vulnerability?lang=en
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c039c8f");
  script_set_attribute(attribute:"solution", value:
"Update the remote host to iDRAC8 firmware 2.70.70.70, or iDRAC9 firmware 3.36.36.36, or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3764");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:remote_access_card");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac8");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac9");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drac_detect.nasl");
  script_require_keys("installed_sw/iDRAC");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
include('http.inc');

port = get_http_port(default:443, embedded:TRUE);

app_info = vcf::idrac::get_app_info(port:port);

constraints = [
  {'idrac':'8', 'min_version':'1.0', 'fixed_version':'2.70.70.70'},
  {'idrac':'9', 'min_version':'1.0', 'fixed_version':'3.36.36.36'}
];

vcf::idrac::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
