##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162139);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/14");

  script_cve_id("CVE-2022-23704");

  script_name(english:"iLO 4 < 2.80 DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote HPE Integrated Lights-Out (iLO) server's web interface is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"A potential security vulnerability has been identified in Integrated Lights-Out 4 (iLO 4). The vulnerability could
allow remote Denial of Service. The vulnerability is resolved in Integrated Lights-Out 4 (iLO 4) 2.80 and later.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=emr_na-hpesbhf04240en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?707fc0ba");
  script_set_attribute(attribute:"solution", value:
"Upgrade firmware to 2.80 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23704");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:integrated_lights-out_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ilo_detect.nasl");
  script_require_keys("www/ilo", "ilo/generation", "ilo/firmware");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('vcf_extras.inc');

var port = get_http_port(default:80, embedded: TRUE);
var app_info = vcf::get_app_info(app:'ilo', port:port, webapp:TRUE);

vcf::ilo::check_superdome(audit:TRUE);

var constraints = [
  {'generation' : '4', 'fixed_version' : '2.80'}
];
vcf::ilo::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
