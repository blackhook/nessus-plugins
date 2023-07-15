#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144756);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-26198");
  script_xref(name:"IAVA", value:"2021-A-0003-S");

  script_name(english:"Dell iDRAC XSS (DSA-2020-268)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a cross site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"Dell EMC iDRAC9 versions prior to 4.32.10.00 and 4.40.00.00 contain a reflected cross-site scripting vulnerability in
the iDRAC9 web application. A remote attacker could potentially exploit this vulnerability to run malicious HTML or
JavaScript in a victim’s browser by tricking a victim in to following a specially crafted link.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-ie/000181088/dsa-2020-268-dell-emc-idrac9-reflected-xss-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2273d4ac");
  script_set_attribute(attribute:"solution", value:
"Update the remote host to iDRAC9 firmware 4.32.10.00, 4.40.00.00 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26198");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac9");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

constraints = [{'idrac':'9', 'min_version':'1.0', 'fixed_version':'4.32.10.00', 'fixed_display':'4.32.10.00, 4.40.00.00 or later'}];

vcf::idrac::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
