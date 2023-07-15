##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147144);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2021-23840", "CVE-2021-23841");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Tenable SecurityCenter 5.16.x / 5.17.0 Multiple Vulnerabilities (TNS-2021-03)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter application installed on the remote host is in the
5.16.0 - 5.17.0 version range. It is, therefore, affected by multiple vulnerabilities in a third-party component
(OpenSSL). Updated versions have been made available by the providers. OpenSSL has been updated to version 1.1.1j.

Note that Nessus has not tested for these issues nor the stand-alone patch but has instead relied only on the
application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2021-03");
  # https://docs.tenable.com/releasenotes/Content/tenablesc/tenablesc2021022.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92554607");
  script_set_attribute(attribute:"solution", value:
"Apply SC-202102.2 patch or upgrade to version 5.18.0 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23840");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("Host/SecurityCenter/Version", "installed_sw/SecurityCenter");

  exit(0);
}

include('vcf_extras.inc');


# try first local
var local_version = get_kb_item('Host/SecurityCenter/Version');
if (!empty_or_null(local_version))
{
  var app_info = vcf::tenable_sc::get_app_info();
}
else
{
  # otherwise, remote
  var port = get_http_port(default:443, dont_exit:TRUE);
  var app_info = vcf::tenable_sc::get_app_info(port:port);
}

# let's check if the version is within the vulnerable range
var constraints = [
  {'min_version': '5.16.0', 'fixed_version':'5.17.1', 'fixed_display':'Apply SC-202102.2 patch or upgrade to version 5.18.0 or later'}
];

var matching_constraint = vcf::check_version(version:app_info.parsed_version, constraints:constraints);
 
if (!isnull(matching_constraint))
{
  if (!empty_or_null(app_info['installed_patches']) && "SC-202102.2" >< app_info['installed_patches'])
  {
      vcf::audit(app_info);
  }
  else
  {
    if(report_paranoia < 2)
      audit(AUDIT_POTENTIAL_VULN, 'Tenable SecurityCenter', app_info['version']);
    else
      vcf::report_results(app_info:app_info, fix:matching_constraint.fixed_display, severity:SECURITY_WARNING);
  }
    
}
else
  vcf::audit(app_info);
