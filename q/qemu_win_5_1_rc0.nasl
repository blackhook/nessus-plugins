#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138897);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2020-10761",
    "CVE-2020-13791",
    "CVE-2020-15469",
    "CVE-2020-15859"
  );
  script_xref(name:"IAVB", value:"2020-B-0041-S");

  script_name(english:"QEMU 4.2 < 5.1.0-rc0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has virtualization software installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of QEMU installed on the remote Windows host is prior to release 5.1.0-rc0. It is, therefore, affected by 
multiple vulnerabilities:
  A denial of service flaw occurs when an nbd-client sends a spec-compliant request that is near the 
  boundary of maximum permitted request length. A remote nbd-client could use this flaw to crash the 
  qemu-nbd server resulting in a denial of service. (CVE-2020-10761)

  An out-of-bounds error occurs within hw/pci/pci.c. A guest OS user could use this flaw
  by providing an address near the end of the PCI configuration space. (CVE-2020-13791)

  A MemoryRegionOps object may lack read/write callback methods, leading to a NULL pointer dereference.
  (CVE-2020-15469)

  A use-after-free in hw/net/e1000e_core.c because a guest OS user can trigger an e1000e packet with 
  the data's address set to the e1000e's MMIO address. (CVE-2020-15859)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  # https://git.qemu.org/?p=qemu.git;a=commit;h=9f1f264edbdf5516d6f208497310b3eedbc7b74c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9b94deb");
  script_set_attribute(attribute:"see_also", value:"https://wiki.qemu.org/ChangeLog/5.1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to QEMU 5.1.0-rc0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10761");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-13791");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qemu:qemu");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qemu_installed_windows.nbin");
  script_require_keys("installed_sw/QEMU");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'QEMU', win_local:TRUE);

constraints = [{'min_version':'4.2', 'fixed_version' : '5.0.90.0', 'fixed_display':'5.1.0-rc0' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
