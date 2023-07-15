#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157434);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/11");

  script_cve_id("CVE-2022-21986");
  script_xref(name:"IAVA", value:"2022-A-0064-S");

  script_name(english:"Security Update for Visual Studio 2019 (February 2022) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio 2019 runtime installed on the remote macOS or Mac OS X host is missing a security update. 
It is, therefore, affected by the following vulnerability:

  - A Denial of Service vulnerability exists in .NET 6.0 and .NET 5.0 when the Kestrel web server processes
    certain HTTP/2 and HTTP/3 requests.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21986");
  # https://docs.microsoft.com/en-gb/visualstudio/releasenotes/vs2019-mac-relnotes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ffcc8699");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Visual Studio 2019 version 8.10.19.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21986");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/08");

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

var constraints = [{'fixed_version': '8.10.19.11'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
