#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157421);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/09");

  script_cve_id("CVE-2021-22045");
  script_xref(name:"VMSA", value:"2022-0001");
  script_xref(name:"IAVA", value:"2022-A-0039");

  script_name(english:"VMware Fusion 12.x < 12.2.0 Heap Overflow RCE (VMSA-2022-0001)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote macOS or Mac OS X host is affected by a RCE vulnerability");
  script_set_attribute(attribute:"description", value:
"VMware Fusion contains a heap-overflow vulnerability in CD-ROM device emulation. A malicious actor with access to a
virtual machine with CD-ROM device emulation may be able to exploit this vulnerability in conjunction with other
issues to execute code on the hypervisor from a virtual machine.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-0001.html");
  script_set_attribute(attribute:"solution", value:
"Update to VMware Fusion version 12.2.0, or later.");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "installed_sw/VMware Fusion");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled'))
audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var app_info = vcf::get_app_info(app:'VMware Fusion');

var constraints = [
  { 'min_version' : '12.0', 'fixed_version' : '12.2.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
