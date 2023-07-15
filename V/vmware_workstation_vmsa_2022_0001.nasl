#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157422);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/09");

  script_cve_id("CVE-2021-22045");
  script_xref(name:"VMSA", value:"2022-0001");
  script_xref(name:"IAVA", value:"2022-A-0039");

  script_name(english:"VMware Workstation 16.0.x < 16.2.0 Heap Overflow RCE (VMSA-2022-0001)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote host is affected by a RCE vulnerability");
  script_set_attribute(attribute:"description", value:
"VMware Workstation contains a heap-overflow vulnerability in CD-ROM device emulation. A malicious actor with access
to a virtual machine with CD-ROM device emulation may be able to exploit this vulnerability in conjunction with other
issues to execute code on the hypervisor from a virtual machine.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-0001.html");
  script_set_attribute(attribute:"solution", value:
"Update to VMware Workstation version 16.2.0, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22045");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_linux_installed.nbin", "vmware_workstation_detect.nasl");
  script_require_keys("installed_sw/VMware Workstation");

  exit(0);
}

include('vcf.inc');

if (get_kb_item('SMB/Registry/Enumerated')) win_local = TRUE;

var app_info = vcf::get_app_info(app:'VMware Workstation', win_local:win_local);

var constraints = [
  { 'min_version' : '16.0', 'fixed_version' : '16.2.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
