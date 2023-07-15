#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(122244);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/18");

  script_cve_id("CVE-2016-4379");

  script_name(english:"iLO 3 < 1.88 Information Disclosure Vulnerability");
  script_summary(english:"Checks version of HP Integrated Lights-Out (iLO).");

  script_set_attribute(attribute:"synopsis", value:
"The remote HP Integrated Lights-Out (iLO) server's web interface is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"An information disclosure vulnerability exists in iLO 3 before
firmware version 1.88 due to an improper use of a MAC protection
mechanism in conjunction with CBC padding in its TLS implementation.
An unauthenticated, remote attacker can exploit this to disclose
potentially sensitive information.");
  # https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c05249760
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6ed2b464");
  script_set_attribute(attribute:"solution", value:
"Upgrade iLO 3 firmware to 1.88 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4379");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:integrated_lights-out_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var constraints = [{'generation' : '3', 'fixed_version' : '1.88'}];
vcf::ilo::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
