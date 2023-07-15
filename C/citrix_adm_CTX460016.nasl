##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162330);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/01");

  script_cve_id("CVE-2022-27511", "CVE-2022-27512");
  script_xref(name:"IAVA", value:"2022-A-0254");

  script_name(english:"Citrix ADM 13.0.x < 13.0.85.19 / 13.1.x < 13.1.21.53 Multiple Vulnerabilities (CTX460016)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities exist in Citrix Application Delivery Management (ADM) 13.0 prior to 13.0-85.19 and 13.1 prior
to 13.1-21.53. An unauthenticated, remote attacker can exploit this to reset the administrator password and gain
administrative access to the appliance.

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's self-reported
version number.");
  # https://support.citrix.com/article/CTX460016/citrix-application-delivery-management-security-bulletin-for-cve202227511-and-cve202227512
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de07e06e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 13.0.85.19 or 13.1.21.53 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27511");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:application_delivery_management");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_adm_ssh_detect.nbin");
  script_require_keys("installed_sw/Citrix ADM");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Citrix ADM');

var constraints = [
  {'min_version': '13.0', 'fixed_version': '13.0.85.19', 'fixed_display': '13.0-85.19'},
  {'min_version': '13.1', 'fixed_version': '13.1.21.53', 'fixed_display': '13.1-21.53'}
];

vcf::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_HOLE
);
