#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169881);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2021-28821", "CVE-2021-28822");

  script_name(english:"TIBCO Enterprise Message Service Windows Platform < 8.6.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"TIBCO Enterprise Message Service Windows Platform running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of TIBCO Enterprise Message Service Windows Platform running on the remote host is pior to 8.6.0. It is,
therefore, affected by multiple vulnerabilities:

  - A vulnerability that theoretically allows a low privileged attacker with local access on some versions of the
    Windows operating system to insert malicious software. The affected component can be abused to execute the malicious
    software inserted by the attacker with the elevated privileges of the component. This vulnerability results from a
    lack of access restrictions on certain files and/or folders in the installation. (CVE-2021-28821)

  - A vulnerability that theoretically allows a low privileged attacker with local access on the Windows operating
    system to insert malicious software. The affected component can be abused to execute the malicious software inserted
    by the attacker with the elevated privileges of the component. This vulnerability results from the affected
    component searching for run-time artifacts outside of the installation hierarchy. (CVE-2021-28822)

Note that Nessus has not tested for these issues but has instead relied only on the service's self-reported version
number.");
  # https://www.tibco.com/support/advisories/2021/03/tibco-security-advisory-march-23-2021-tibco-enterprise-message-service-2021-28821
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c09252df");
  # https://www.tibco.com/support/advisories/2021/03/tibco-security-advisory-march-23-2021-tibco-enterprise-message-service-2021-28822
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c735937a");
  script_set_attribute(attribute:"solution", value:
"Update to TIBCO Enterprise Message Service 8.6.0 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28822");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tibco:enterprise_message_service");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tibco_ems_remote_detection.nbin");
  script_require_keys("installed_sw/TIBCO Enterprise Message Service");

  exit(0);
}

include('vcf.inc');

var app_name = 'TIBCO Enterprise Message Service';
var app_info = vcf::combined_get_app_info(app:app_name);
var platform = app_info['Platform'];

if (platform != 'Windows')
  audit(AUDIT_INST_VER_NOT_VULN, app_name, app_info.version + ' ' + platform + ' Platform');

var constraints = [
  { 'max_version':'8.5.1', 'fixed_display':'8.6.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
