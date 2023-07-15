#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150961);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/23");

  script_cve_id("CVE-2020-3999");
  script_xref(name:"IAVA", value:"2021-A-0007");
  script_xref(name:"VMSA", value:"2020-0029.1");

  script_name(english:"VMware Workstation 15.0.x < 15.5.7 Vulnerability (VMSA-2020-0029.1)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Windows host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote host is 15.0.x prior to 15.5.7. It is, therefore, affected by
a vulnerability.  Note that Nessus has not tested for these issues but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2020-0029.1.html");
  script_set_attribute(attribute:"see_also", value:"https://my.vmware.com/group/vmware/patch");
  # https://docs.vmware.com/en/VMware-vSphere/7.0/rn/vsphere-esxi-70u1c.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be61d650");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/go/downloadworkstation");
  script_set_attribute(attribute:"see_also", value:"https://docs.vmware.com/en/VMware-Workstation-Pro/index.html");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/go/downloadplayer");
  script_set_attribute(attribute:"see_also", value:"https://docs.vmware.com/en/VMware-Workstation-Player/index.html");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/go/downloadworkstation");
  script_set_attribute(attribute:"see_also", value:"https://docs.vmware.com/en/VMware-Workstation-Pro/index.html");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/go/downloadplayer");
  script_set_attribute(attribute:"see_also", value:"https://docs.vmware.com/en/VMware-Workstation-Player/index.html");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/go/downloadfusion");
  script_set_attribute(attribute:"see_also", value:"https://docs.vmware.com/en/VMware-Fusion/index.html");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/go/downloadfusion");
  script_set_attribute(attribute:"see_also", value:"https://docs.vmware.com/en/VMware-Fusion/index.html");
  # https://docs.vmware.com/en/VMware-Cloud-Foundation/4.2/rn/VMware-Cloud-Foundation-42-Release-Notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f86ed8df");
  # https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c0a88f70");
  script_set_attribute(attribute:"solution", value:
"Update to VMware Workstation version 15.5.7, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3999");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_detect.nasl", "vmware_workstation_linux_installed.nbin");
  script_require_keys("Host/VMware Workstation/Version");

  exit(0);
}

include('vcf.inc');

if (get_kb_item('SMB/Registry/Enumerated')) win_local = TRUE;

app_info = vcf::get_app_info(app:'VMware Workstation', win_local:win_local);

constraints = [
  { 'min_version' : '15.0', 'fixed_version' : '15.5.7' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
