##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146962);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/15");

  script_cve_id("CVE-2021-20076");

  script_name(english:"Tenable SecurityCenter 5.13.0 - 5.17.0 Remote Code Execution (TNS-2021-03)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter application installed on the remote host is in the
5.13.0 through 5.17.0 version range. Tenable.sc and Tenable.sc Core versions 5.13.0 through 5.17.0 were found to contain
a vulnerability that could allow an authenticated, unprivileged user to perform Remote Code Execution (RCE) on the
Tenable.sc server via Hypertext Preprocessor unserialization.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2021-03");
  script_set_attribute(attribute:"solution", value:
"See Tenable advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20076");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("Host/SecurityCenter/Version", "installed_sw/SecurityCenter");

  exit(0);
}

include('vcf_extras.inc');

var local_version, app_info, port, constraints, matching_constraint;

# try first local
local_version = get_kb_item('Host/SecurityCenter/Version');

if (!empty_or_null(local_version))
{
  app_info = vcf::tenable_sc::get_app_info();
  # let's check if the version is within the vulnerable range
  constraints = [
    {'min_version': '5.13.0', 'fixed_version':'5.17.1', 'fixed_display':'Apply SC-202103.1 patch or upgrade to version 5.18.0 or later'}
  ];
}

# otherwise, remote
else 
{
  port = get_http_port(default:443, dont_exit:TRUE);
  app_info = vcf::tenable_sc::get_app_info(port:port);
  constraints = [{
    'min_version': '5.13.0', 
    'fixed_version':'5.17.1', 
    'fixed_display':'If you have not already done so, apply SC-202103.1 patch or upgrade 
  to version 5.18.0 or later.\n
  Note, this scan was unable to enumerate installed patches for the detected installation
  of Tenable.sc, becuase no credentials were provided for the scan.'
  }];
}

matching_constraint = vcf::check_version(version:app_info.parsed_version, constraints:constraints);

if (!isnull(matching_constraint))
{
  # if patch is installed, audit not affected
  if (!empty_or_null(app_info['installed_patches']) && "SC-202103.1" >< app_info['installed_patches'])
    vcf::audit(app_info);

  # conditional paranoid check - only require paranoid if the T.sc detection is remote
  # remote detection means we cannot enumerate isntalled patches, so potentially vuln
  else
  {   
    if(report_paranoia < 2 && (!local_version))
      audit(AUDIT_POTENTIAL_VULN, 'Tenable SecurityCenter', app_info['version']);
    else
      vcf::report_results(app_info:app_info, fix:matching_constraint.fixed_display, severity:SECURITY_WARNING);
  }
}

else
  vcf::audit(app_info);

