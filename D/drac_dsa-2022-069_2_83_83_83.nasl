#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159643);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/03");

  script_cve_id("CVE-2022-24423");

  script_name(english:"Dell EMC iDRAC8 < 2.83.83.83 (DSA-2022-069)");

  script_set_attribute(attribute:"synopsis", value:
"Dell EMC iDRAC8 installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Dell EMC iDRAC8 installed on the remote host is prior to 2.83.83.83. It is, therefore, affected by a
vulnerability as referenced in the DSA-2022-069 advisory.

  - Dell EMC iDRAC8 versions 2.81.81 and earlier contain a denial of service vulnerability. A remote
    unauthenticated attacker could potentially exploit this vulnerability to cause resource exhaustion,
    resulting in a denial of service (DoS) condition. (CVE-2022-24423)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.dell.com/support/kbdoc/en-us/000198064/dsa-2022-069");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell EMC iDRAC8 version 2.83.83.83 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24423");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:emc_idrac8");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:dell:emc_idrac8");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drac_detect.nasl");
  script_require_keys("installed_sw/iDRAC");

  exit(0);
}

include('vcf_extras.inc');
include('http.inc');

var port = get_http_port(default:443, embedded:TRUE);
var app_info = vcf::idrac::get_app_info(port:port);
var constraints = [
{ 'fixed_version' : '2.83.83.83', 'idrac' : '8' }
];
vcf::idrac::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
