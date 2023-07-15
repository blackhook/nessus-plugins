#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137071);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-9859");
  script_xref(name:"APPLE-SA", value:"HT211215");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2020-05-30");
  script_xref(name:"IAVA", value:"2020-A-0227-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"macOS 10.15.x < 10.15.5 Supplemental Update / 10.13.x < 10.13.6 Security Update 2020-003");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS or Mac OS X security update or supplemental update that fixes a remote code execution vulnerability");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 10.15.x prior to 10.15.5 Supplemental Update, 10.13.x
prior to 10.13.6 Security Update 2020-003. It is, therefore, affected by a remote code execution vulnerability :

  - An application may be able to execute arbitrary code
    with kernel privileges (CVE-2020-9859)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT211215");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 10.15.x < 10.15.5 Supplemental Update / 10.13.x < 10.13.6 Security Update 2020-003 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9859");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('lists.inc');
include('vcf_extras_apple.inc');

app_info = vcf::apple::macos::get_app_info();

constraints = [
  { 'min_version' : '10.15', 'max_version' : '10.15.5', 'fixed_build' : '19F101', 'fixed_display' : '10.15.5 Supplemental Update' },
  { 'min_version' : '10.13', 'max_version' : '10.13.6', 'fixed_build' : '17G13035', 'fixed_display' : '10.13.6 Security Update 2020-003' }
];

vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
