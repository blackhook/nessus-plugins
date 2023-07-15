##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(140696);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/26");

  script_cve_id("CVE-2020-14509", "CVE-2020-14517", "CVE-2020-14519");

  script_name(english:"CodeMeter < 7.10a Multiple Vulnerabilities");
  script_summary(english:"Checks the CodeMeter WebAdmin version.");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is affected by a privilege
escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the CodeMeter WebAdmin server
installed on the remote host is prior to 7.10a. It is, therefore, 
affected by multiple vulnerabilities :

  - Multiple memory corruption vulnerabilities exist where the packet
    parser mechanism does not verify length fields. An attacker could
    send specially crafted packets to exploit these vulnerabilities. 
    (CVE-2020-14509)

  - Protocol encryption can be easily broken and the server accepts
    external connections, which may allow an attacker to remotely
    communicate with the CodeMeter API. (CVE-2020-14517)

  - Use of the internal WebSockets API via a specifically crafted
    Java Script payload, which may allow alteration or creation of
    license files when combined with CVE-2020-14515. (CVE-2020-14519)");

  script_set_attribute(attribute:"see_also", value:"https://www.wibu.com/support/user/downloads-user-software.html");
  # https://www.wibu.com/fileadmin/wibu_downloads/security_advisories/Advisory_WIBU-200521-02.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09fcfe01");
  # https://www.wibu.com/fileadmin/wibu_downloads/security_advisories/Advisory_WIBU-200521-03.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4f6b830");
  # https://www.wibu.com/fileadmin/wibu_downloads/security_advisories/Advisory_WIBU-200521-04.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18b81c34");
  # https://us-cert.cisa.gov/ics/advisories/icsa-20-203-01
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c85150b5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to CodeMeter 7.10a (7.10.4196.501) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14509");

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

var app = 'CodeMeter';
get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:22352, embedded:TRUE);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

var constraints = [
  {'fixed_version': '7.10.4196.501'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
