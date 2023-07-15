#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(143123);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/24");

  script_cve_id("CVE-2020-4693");

  script_name(english:"IBM Spectrum Protect Operations Center 7.1.x < 7.1.11.000 / 8.1.x < 8.1.10.000 Code Injection Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a code 
code injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The IBM Spectrum Protect Operations Center running on the remote
host is version 7.1.x < 7.1.11.000 or 8.1.x < 8.1.10.000. It is, 
therefore, vulnerable to a code injection vulnerability which
could allow an unauthenticated, remote attacker to execute
arbitrary code on the system.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6325341");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Spectrum Protect 7.1.11.000 / 8.1.10.000 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4693");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:spectrum_protect_operations_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_spectrum_protect_oc_detect.nbin");
  script_require_ports("installed_sw/IBM Spectrum Protect Operations Center");

  exit(0);
}

include('vcf.inc');
include('http.inc');

app = 'IBM Spectrum Protect Operations Center';
port = get_http_port(default:11090); 
app_info = vcf::get_app_info(app:app, webapp:TRUE, port:port);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '7.1', 'fixed_version' : '7.1.11.000' },
  { 'min_version' : '8.1', 'fixed_version' : '8.1.10.000' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
