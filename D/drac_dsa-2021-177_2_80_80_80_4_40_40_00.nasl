##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161798);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/05");

  script_cve_id("CVE-2021-36301");
  script_xref(name:"IAVA", value:"2022-A-0225-S");

  script_name(english:"Dell EMC iDRAC8 < 2.80.80.80 / Dell EMC iDRAC9 < 4.40.40.00 (DSA-2021-177)");

  script_set_attribute(attribute:"synopsis", value:
"Dell EMC iDRAC8/Dell EMC iDRAC9 installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Dell EMC iDRAC8 or Dell EMC iDRAC9 installed on the remote host is affected by a vulnerability as
referenced in the DSA-2021-177 advisory:

  - Dell iDRAC 9 prior to version 4.40.40.00 and iDRAC 8 prior to version 2.80.80.80 contain a Stack Buffer
    Overflow in Racadm. An authenticated remote attacker may potentially exploit this vulnerability to control
    process execution and gain access to the underlying operating system. (CVE-2021-36301)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-us/000191229/dsa-2021-177-dell-emc-idrac-security-update-for-multiple-security-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13d440ac");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell EMC iDRAC8 version 2.80.80.80 or later. Upgrade to Dell EMC iDRAC9 version 4.40.40.00 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36301");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:emc_idrac8");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:emc_idrac9");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:dell:emc_idrac8");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:dell:emc_idrac9");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drac_detect.nasl");
  script_require_keys("installed_sw/iDRAC");

  exit(0);
}

include('vcf_extras.inc');
include('http.inc');

var port = get_http_port(default:443, embedded:TRUE);
var app_info = vcf::idrac::get_app_info(port:port);
var constraints = [
{ 'fixed_version' : '2.80.80.80', 'idrac' : '8' },
{ 'fixed_version' : '4.40.40.00', 'idrac' : '9' }
];
vcf::idrac::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
