##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143117);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/24");

  script_cve_id("CVE-2020-3981", "CVE-2020-3982", "CVE-2020-3995");
  script_xref(name:"VMSA", value:"2020-0023");
  script_xref(name:"IAVA", value:"2020-A-0468");

  script_name(english:"VMware Fusion 11.0.x < 11.5.6 Multiple Vulnerabilities (VMSA-2020-0023)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of VMware Fusion installed on the remote macOS or Mac OS
X host is 11.0.x prior to 11.5.6. It is, therefore, affected by the
following vulnerabilities:

  - A time-of-check time-of-use flaw exists related to ACPI device
    handling that allows an authenticated administrator to leak
    memory from the vmx process. (CVE-2020-3981)

  - A time-of-check time-of-use flaw exists related to ACPI device
    handling that allows an authenticated administrator to crash the
    vmx process or corrupt the hypervisor's memory heap.
    (CVE-2020-3982)

  - An unspecified flaw exists related to the VMCI host drivers that
    allows an attacker having access to the virtual machine to cause
    denial of service conditions via resource exhaustion.
    (CVE-2020-3995)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2020-0023.html");
  script_set_attribute(attribute:"solution", value:
"Update to VMware Fusion version 11.5.6, 12.0, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3982");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "installed_sw/VMware Fusion");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'VMware Fusion');

constraints = [
  { 'min_version' : '11.0', 'fixed_version' : '11.5.6', 'fixed_display' : '11.5.6 / 12.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
