##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144198);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_name(english:"SolarWinds Orion Platform 2019.4 HF5 / 2020.2.x < 2020.2.1 SUNBURST Malware Backdoor");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by a malware backdoor.");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds Orion Platform running on the remote host is
2019.4 HF5 or 2020.2.1 prior to 2020.2.1 HF2. It is, therefore, affected by a
malware backdoor known as SUNBURST. The file
SolarWinds.Orion.Core.BusinessLayer.dll that is included in these versions is
known to contain a backdoor that communicates to third party servers and
could allow a remote attacker complete control over the host via obfuscated,
benign looking network traffic.

The United States Department of Homeland Security has issued Emergency
Directive 21-01 that specifies SolarWinds Orion products up to and including
2020.2.1 HF 1 are currently being exploited by malicious actors.

Note that Nessus has not tested for this issue but has instead relied only on
the application's self-reported version number.");
  # https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85b4fa56");
  script_set_attribute(attribute:"see_also", value:"https://www.solarwinds.com/securityadvisory");
  script_set_attribute(attribute:"see_also", value:"https://cyber.dhs.gov/ed/21-01/");
  # https://www.tenable.com/blog/solorigate-solarwinds-orion-platform-contained-a-backdoor-since-march-2020-sunburst
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ff24ea2");
  # https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?901aa5a2");
  # https://support.solarwinds.com/SuccessCenter/s/article/Orion-Platform-2019-4-Hotfix-6?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?704c04b1");
  # https://documentation.solarwinds.com/en/Success_Center/orionplatform/content/release_notes/orion_platform_2020-2-1_release_notes.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbd97140");

  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds Orion Platform 2019.4 HF6, 2020.2.1 HF2, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_platform");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_orion_npm_detect.nasl", "solarwinds_orion_installed.nbin");
  script_require_keys("installed_sw/SolarWinds Orion Core");
  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::solarwinds_orion::initialize();
app_info = vcf::solarwinds_orion::combined_get_app_info();

constraints = [
  { 'min_version' : '2020.2', 'fixed_version' : '2020.2.1' },
  { 'equal' : '2019.4 HF5', 'fixed_version' : '2019.4 HF6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
