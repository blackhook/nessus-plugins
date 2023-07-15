#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168861);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/19");

  script_cve_id("CVE-2022-4172");
  script_xref(name:"IAVB", value:"2022-B-0057");

  script_name(english:"QEMU < 7.2.0 Overflow (CVE-2022-4172)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has virtualization software installed that is affected by an overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"An integer overflow and buffer overflow issues were found in the ACPI Error Record Serialization Table (ERST) device 
of QEMU in the read_erst_record() and write_erst_record() functions. Both issues may allow the guest to overrun the 
host buffer allocated for the ERST memory device. A malicious guest could use these flaws to crash the QEMU process 
on the host.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  # https://lore.kernel.org/qemu-devel/20221024154233.1043347-1-lk@c--e.de/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3092478e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to QEMU 7.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4172");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qemu:qemu");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qemu_installed_windows.nbin");
  script_require_keys("installed_sw/QEMU");

  exit(0);
}

include('vcf.inc');

var app = 'QEMU';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

# Paranoid due to uncertain min_version, max_version found by searching releases for last one where
# https://git.qemu.org/?p=qemu.git;a=commitdiff;h=c2cb511634012344e3d0fe49a037a33b12d8a98a isn't uupdated
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, app, app_info.version);

var constraints = [{'min_version':'7.0.0', 'max_version' : '7.2.0-rc0', 'fixed_display':'7.2.0' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
