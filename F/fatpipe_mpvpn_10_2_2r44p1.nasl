#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176379);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/26");

  script_cve_id("CVE-2021-27860");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/01/24");
  script_xref(name:"CEA-ID", value:"CEA-2023-0017");

  script_name(english:"FatPipe MPVPN < 10.1.2r60p92 / 10.2.2 < 10.2.2r44p1 Configuration File Upload (CVE-2021-27860)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote server is affected by a configuration file upload vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of FatPipe MPVPN running on the remote web server is <
10.1.2r60p92 or 10.2.2 < 10.2.2r44p1. It is, therefore, affected by a configuration file upload vulnerability that could
allow a remote attacker to upload a file to any location on the filesystem on an affected device.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fatpipeinc.com/fpsa/fpsa006.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to FatPipe MPVPN 10.1.2r60p92 or 10.2.2r44p1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27860");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fatpipeinc:mpvpn_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fatpipe_mpvpn_web_detect.nbin");
  script_require_keys("installed_sw/FatPipe MPVPN");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:'FatPipe MPVPN', port:port, webapp:TRUE);

var constraints = [
  {'fixed_version':'10.1.2.60.92', 'fixed_display':'10.1.2r60p92'},
  {'min_version':'10.2.2', 'fixed_version':'10.2.2.44.1', 'fixed_display':'10.2.2r44p1'},
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);