#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177307);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/15");

  script_cve_id("CVE-2023-0664", "CVE-2023-0330");
  script_xref(name:"IAVB", value:"2023-B-0019");

  script_name(english:"QEMU < 8.0.0 Multiple Vulnerabilites (CVE-2023-0664)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has virtualization software installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"- A flaw was found in the QEMU Guest Agent service for Windows. A local unprivileged user may be able to manipulate 
    the QEMU Guest Agent's Windows installer via repair custom actions to elevate their privileges on the system.

  - A vulnerability in the lsi53c895a device affects the latest version of qemu. A DMA-MMIO reentrancy problem may lead to memory corruption bugs like stack overflow or use-after-free.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2167423");
  # https://lists.nongnu.org/archive/html/qemu-devel/2023-01/msg03411.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6b4d8fc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to QEMU 8.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0664");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qemu:qemu");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qemu_installed_windows.nbin");
  script_require_keys("installed_sw/QEMU");

  exit(0);
}

include('vcf.inc');

var app = 'QEMU';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

# Paranoid due to uncertain min_version, max_version found by searching releases for last one where
# https://git.qemu.org/?p=qemu.git;a=commitdiff;h=c2cb511634012344e3d0fe49a037a33b12d8a98a isn't updated
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, app, app_info.version);

var constraints = [{'max_version' : '8.0.0-rc0', 'fixed_display':'8.0.0' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);