##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146309);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/26");

  script_cve_id("CVE-2021-25274");

  script_name(english:"SolarWinds Orion Platform < 2019.4.2 Remote Code Execution");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Collector Service in SolarWinds Orion Platform before 2019.4.2 uses MSMQ (Microsoft Message Queue) and doesn't set
permissions on its private queues. As a result, remote unauthenticated clients can send messages to TCP port 1801 that
the Collector Service will process. Additionally, upon processing of such messages, the service deserializes them in
insecure manner, allowing remote arbitrary code execution as LocalSystem.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://documentation.solarwinds.com/en/Success_Center/orionplatform/content/release_notes/orion_platform_2019-4-2_release_notes.htm#link4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?413ea028");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds Orion Platform 2019.4.2 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25274");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_platform");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_orion_npm_detect.nasl", "solarwinds_orion_installed.nbin");
  script_require_keys("installed_sw/SolarWinds Orion Core");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::solarwinds_orion::initialize();
app_info = vcf::solarwinds_orion::combined_get_app_info();

# A hotfix exists which fixes CVE-2021-25274
# Check for 2019.2 with hotfix >= 4
# https://support.solarwinds.com/SuccessCenter/s/article/Orion-Platform-2019-2-Hotfix-4?language=en_US
if  (app_info.version =~  "^2019\.2" && ver_compare(ver:app_info.Hotfix, fix:"4") >= 0)
  audit(AUDIT_HOST_NOT, "affected");

constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '2019.4.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
