##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('compat.inc');

if (description)
{
  script_id(161121);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id("CVE-2022-23267", "CVE-2022-29145");
  script_xref(name:"IAVA", value:"2022-A-0198");

  script_name(english:"Security Update for Visual Studio 2019 (May 2022) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products installed on the remote macOS or Mac OS X host is missing a security update. 
It is, therefore, affected by denial of service vulnerability:

  - A denial of service (DoS) vulnerability exists in Microsoft Visual Studio 2019. An unauthenticated, 
    remote attacker can exploit this issue to cause the application to stop responding. 
    (CVE-2022-29145, CVE-2022-23267)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported
version");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2019-mac-relnotes#8123
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d14ed97");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
        - Update 8.10.23.7 for Visual Studio 2019");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23267");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-29145");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("visual_studio_mac_installed.nbin");
  script_require_keys("installed_sw/Visual Studio", "Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version')) audit(AUDIT_OS_NOT, 'macOS / Mac OS X');

var app_info = vcf::get_app_info(app:'Visual Studio');
vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [ {'product': '2019', 'min_version': '8.10', 'fixed_version': '8.10.23.7'} ];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
