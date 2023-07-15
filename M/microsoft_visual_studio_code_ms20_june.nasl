#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137728);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-1343");

  script_name(english:"Security Update for Microsoft Visual Studio Code Live Share Extension (June 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An information disclosure vulnerability exists in Visual Studio Code Live Share Extension when it exposes tokens in
plain text. To exploit the vulnerability, an attacker would need to perform a successful capture of the tokens from
client to proxy, where specific proxy settings are being used, making this very difficult to exploit.

The update address the vulnerability by modifying the way Visual Studio Code Live Share communicates with clients to
proxies.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1343
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b713d3be");
  # https://marketplace.visualstudio.com/items/MS-vsliveshare.vsliveshare/changelog
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3cd40728");
  script_set_attribute(attribute:"see_also", value:"https://github.com/MicrosoftDocs/live-share/releases");
  script_set_attribute(attribute:"solution", value:
"Please see Microsoft security advisory for patch-information");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1343");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_code");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_visual_studio_code_win_extensions_installed.nbin");
  script_require_keys("installed_sw/Microsoft Visual Studio Code");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'vs-code::vsliveshare', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'fixed_version' : '1.0.2354' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);