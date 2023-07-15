#
# (C) Tenable Network Security, Inc.
#

#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134976);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/18");

  script_cve_id("CVE-2018-7105");
  script_bugtraq_id(105425);

  script_name(english:"iLO 3 < 1.90 / iLO 4 < 2.61 / iLO 5 < 1.35 Remote Code Execution Vulnerability (HPESBHF03866)");

  script_set_attribute(attribute:"synopsis", value:
"The remote HP Integrated Lights-Out (iLO) server's web interface 
  is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"A remote command execution vulnerability exists in 
HPE Integrated Lights-Out 5 (iLO 5) for HPE Gen10 Servers prior to v1.35, 
HPE Integrated Lights-Out 4 (iLO 4) prior to v2.61, HPE Integrated Lights-Out 3 (iLO 3) 
prior to v1.90 could be remotely exploited to execute arbitrary code leading to disclosure 
of information. An authenticated, remote attacker can exploit this to bypass authentication and execute 
arbitrary commands.");
  # https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=emr_na-hpesbhf03866en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27f0bcb2");
  script_set_attribute(attribute:"solution", value:
"Upgrade firmware of For iLO 3, upgrade firmware to 1.90 or later.  
For iLO 4, upgrade firmware to 2.61 or later. For iLO 5, upgrade firmware to 1.35 or later.
Alternatively, apply the workarounds outlined in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7105");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:integrated_lights-out_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'generation': '3', 'fixed_version' : '1.90'},
  {'generation': '4', 'fixed_version' : '2.61'},
  {'generation': '5', 'fixed_version' : '1.35'},
  {'moonshot': TRUE,  'fixed_version' : '1.58'}
];
vcf::ilo::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
