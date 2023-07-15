##
# (C) Tenable, Inc. 
##

include('compat.inc');

if (description)
{
  script_id(162392);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/07");

  script_cve_id("CVE-2022-23267", "CVE-2022-24513", "CVE-2022-30184");

  script_name(english:"Security Updates for Visual Studio 2019/2022 (June 2022) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products installed on the remote macOS or Mac OS X host is missing a security update. 
It is, therefore, affected by the following vulnerabilities:

  - A potential privilege escalation vulnerability. An attacker can exploit this to elevate their privileges. 
    (CVE-2022-24513)

  - A potetnial Denial Of Service vulnerability. An attacker can exploit this to create a denial of service. 
    (CVE-2022-23267)

  - An information disclosure vulnerability. An attacker canm exploit this to disclose potentially sensitive
    information. (CVE-2022-30184)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2019-mac-relnotes#8124
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df025a51");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2022/mac-release-notes#17.0.3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?008b5297");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released  to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24513");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("visual_studio_mac_installed.nbin");
  script_require_keys("installed_sw/Visual Studio", "Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version')) audit(AUDIT_OS_NOT, 'macOS / Mac OS X');

var app_info = vcf::get_app_info(app:'Visual Studio');
vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  {'product': '2019', 'min_version': '8.10', 'fixed_version': '8.10.24.14'},
  {'product': '2022', 'min_version': '17.0', 'fixed_version': '17.0.3.21'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);