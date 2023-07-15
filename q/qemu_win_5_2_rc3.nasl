##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143479);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id("CVE-2020-28916");
  script_xref(name:"IAVB", value:"2020-B-0075-S");

  script_name(english:"QEMU < 5.2.0-rc3 Heap Use-After-Free DoS (CVE-2020-28916)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has virtualization software installed that is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of QEMU installed on the remote Windows host may be affected by a denial of service (DoS) vulnerability in
the e1000e device emulator due to a heap use-after-free. An attacker can exploit this by sending packets to be received by
e1000e_write_packet_to_guest() in order to induce a DoS.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.openwall.com/lists/oss-security/2020/12/01/2");
  script_set_attribute(attribute:"see_also", value:"https://bugs.launchpad.net/qemu/+bug/1892978");
  script_set_attribute(attribute:"solution", value:
"Upgrade to QEMU 5.2.0-rc3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28916");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qemu:qemu");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qemu_installed_windows.nbin");
  script_require_keys("installed_sw/QEMU", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

# Paranoid due to uncertain min_version, max_version found by searching releases for last one where
# https://git.qemu.org/?p=qemu.git;a=commitdiff;h=c2cb511634012344e3d0fe49a037a33b12d8a98a isn't uupdated
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:'QEMU', win_local:TRUE);

constraints = [{'min_version':'0.0', 'max_version' : '5.1.92.0', 'fixed_display':'5.2.0-rc3' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
