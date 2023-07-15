##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160544);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-1273");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");

  script_name(english:"Spring Data Commons < 1.13.11 / 2.x < 2.0.6 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The version of Spring Data Commons installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Spring Data Commons installed on the remote host is affected by a remote code execution vulnerability.
Spring Data Commons, versions prior to 1.13 to 1.13.10, 2.0 to 2.0.5, and older unsupported versions, contain a property
binder vulnerability caused by improper neutralization of special elements. An unauthenticated remote malicious user (or
 attacker) can supply specially crafted request parameters against Spring Data REST backed HTTP resources or using
Spring Data's projection-based request payload binding hat can lead to a remote code execution attack.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://tanzu.vmware.com/security/cve-2018-1273");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Spring Data Commons version 1.13.11, 2.0.6, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1273");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Spring Data Commons RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pivotal_software:spring_data_commons");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pivotal_software_spring_data_commons_installed.nbin");
  script_require_keys("installed_sw/Spring Data Commons");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Spring Data Commons');

var constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '1.13.11' },
  { 'min_version' : '2.0', 'fixed_version' : '2.0.6' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
