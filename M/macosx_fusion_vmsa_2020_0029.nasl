##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144851);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/12");

  script_cve_id("CVE-2020-3999");
  script_xref(name:"VMSA", value:"2020-0029");
  script_xref(name:"IAVA", value:"2021-A-0007");

  script_name(english:"VMware Fusion 11.x < 11.5.7 DoS (VMSA-2020-0029)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote macOS or Mac OS X host is affected by a DoS vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of VMware Fusion installed on the remote macOS or Mac OS X host is 11.x prior to 11.5.7. It is,
therefore, affected by a DoS vulnerability due to improper input validation in GuestInfo. A malicious actor with normal
user privilege access to a virtual machine can crash the virtual machine's vmx process leading to a denial of service
condition.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2020-0029.html");
  script_set_attribute(attribute:"solution", value:
"Update to VMware Fusion version 11.5.7, 12, or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3999");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "installed_sw/VMware Fusion");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled'))
audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

app_info = vcf::get_app_info(app:'VMware Fusion');

constraints = [
  { 'min_version' : '11.0', 'fixed_version' : '11.5.7', 'fixed_display' : '11.5.7 / 12' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
