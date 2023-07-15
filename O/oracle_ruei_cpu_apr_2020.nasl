#
# (C) Tenable Network Security, Inc.
#

#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135705);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/23");

  script_cve_id("CVE-2018-11058");
  script_bugtraq_id(108106);
  script_xref(name:"IAVA", value:"2020-A-0150");

  script_name(english:"Oracle Real User Experience Insight (Apr 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a buffer overflow vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Real User Experience Insight installed on the remote host is missing the April 2020 CPU. It is, 
therefore, affected by a buffer overflow condition due to insufficient validation of user-supplied input. An 
unauthenticated, remote attacker can exploit this, by sending specially crafted ASN.1 data to an affected host, to 
cause a denial of service condition or the execution of arbitrary code.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version");
  # https://www.oracle.com/security-alerts/cpuapr2020.html#AppendixEM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ffb7f13c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version as referenced in the April 
  2020 CPU");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11058");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager_grid_control");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_ruei_detect.nbin");
  script_require_keys("installed_sw/Oracle Real User Experience Insight", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('http.inc');
include('vcf.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

port = get_http_port(default:443);
app_info = vcf::get_app_info(app:'Oracle Real User Experience Insight', port:port, webapp:TRUE);

constraints = [
  { 'min_version' : '13.1.2', 'fixed_version' : '13.1.2.1' },
  { 'min_version' : '13.2.3', 'fixed_version' : '13.2.3.1', 'fixed_display' : '13.2.3.1 / 13.3.1.0' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
