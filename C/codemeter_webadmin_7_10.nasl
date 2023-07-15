#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140695);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/26");

  script_cve_id("CVE-2020-16233");

  script_name(english:"CodeMeter < 7.10 Information Exfiltration Vulnerability");
  script_summary(english:"Checks the CodeMeter WebAdmin version.");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is affected by a privilege
escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the CodeMeter WebAdmin server
installed on the remote host is prior to 7.10. It is
affected by a vulnerability where attacker could send a specially
crafted packet that could have the server send back packets
containing data from the heap.");
  script_set_attribute(attribute:"see_also", value:"https://www.wibu.com/support/user/downloads-user-software.html");
  # https://www.wibu.com/fileadmin/wibu_downloads/security_advisories/Advisory_WIBU-200521-05.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2062e436");
  # https://us-cert.cisa.gov/ics/advisories/icsa-20-203-01
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c85150b5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to CodeMeter 7.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16233");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wibu:codemeter_runtime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("codemeter_webadmin_detect.nasl");
  script_require_keys("installed_sw/CodeMeter");
  script_require_ports("Services/www", 22350, 22352);

  exit(0);
}

include('vcf.inc');
include('http.inc');

app = 'CodeMeter';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:22352, embedded:TRUE);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  {'fixed_version': '7.10'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
