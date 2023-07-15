#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153176);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/13");

  script_cve_id("CVE-2019-9548");

  script_name(english:"Citrix ADM Authentication Bypass (CTX247738)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"An information disclosure vulnerability exists in Citrix Application Delivery Management (ADM). An unauthenticated,
remote attacker can exploit this to disclose information could be used for privilege escalation beyond the agent system.

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX247738");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 12.1-50.33, 13.0-33.23 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9548");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:application_delivery_management");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_adm_ssh_detect.nbin");
  script_require_keys("installed_sw/Citrix ADM");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Citrix ADM');

var constraints = [
  {'min_version': '12.0', 'fixed_version': '12.1.50.33', 'fixed_display': '12.1-50.33'},
  {'min_version': '13.0', 'fixed_version': '13.0.33.23', 'fixed_display': '13.0-33.23'}
];

vcf::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_HOLE
);