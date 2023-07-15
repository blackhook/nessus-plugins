#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(122190);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/18");

  script_cve_id("CVE-2015-2106");

  script_name(english:"iLO 2 < 2.27 / iLO 3 < 1.82 / iLO 4 < 2.10 Denial of Service Vulnerability");
  script_summary(english:"Checks version of HP Integrated Lights-Out (iLO).");

  script_set_attribute(attribute:"synopsis", value:
"The remote HP Integrated Lights-Out (iLO) server's web interface is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Integrated Lights-Out
(iLO) due to an undisclosed vulnerability. 
An unauthenticated, remote attacker can exploit this issue to cause 
the application to stop responding.");
  # https://h20564.www2.hp.com/portal/site/hpsc/public/kb/docDisplay?docId=emr_na-c04582368
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c250bedf");
  # https://nvd.nist.gov/vuln/detail/CVE-2015-2106
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01654ca1");
  script_set_attribute(attribute:"solution", value:
"For iLO 2, upgrade firmware to 2.27 or later. For iLO 3, upgrade firmware to 1.82 or later.
For iLO 4, upgrade firmware to 2.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2106");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:integrated_lights-out_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ilo_detect.nasl");
  script_require_keys("www/ilo", "ilo/generation", "ilo/firmware", "ilo/cardtype");
  script_require_ports("Services/www", 80);

  exit(0);
}

#Exit for EOL'd Proliant Hardware, just looks for non-match to futureproof against next gen.
if (get_kb_item("ilo/cardtype") != "Integrity") {
  audit(AUDIT_HOST_NOT, "Integrity based ILO");
}

include('http.inc');
include('vcf.inc');
include('vcf_extras.inc');

var port = get_http_port(default:80, embedded: TRUE);
var app_info = vcf::get_app_info(app:'ilo', port:port, webapp:TRUE);
vcf::ilo::check_superdome(audit:TRUE);

var constraints = [
  {'generation' : '2', 'fixed_version' : '2.27'},
  {'generation' : '3', 'fixed_version' : '1.82'},
  {'generation' : '4', 'fixed_version' : '2.10'}
];
vcf::ilo::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

