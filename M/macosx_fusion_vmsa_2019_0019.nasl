#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130454);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2019-5536");
  script_xref(name:"VMSA", value:"2019-0019");
  script_xref(name:"IAVA", value:"2019-A-0403");

  script_name(english:"VMware Fusion < 11.5.0 Vulnerability (VMSA-2019-0019)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote macOS or Mac OS X host is affected by denial of service");
  script_set_attribute(attribute:"description", value:
"VMware ESXi (6.7 before ESXi670-201908101-SG and 6.5 before ESXi650-201910401-SG), Workstation (15.x before 15.5.0) and Fusion (11.x before 11.5.0) contain a denial-of-service vulnerability in the shader functionality. Successful exploitation of this issue may allow attackers with normal user privileges to create a denial-of-service condition on their own VM. Exploitation of this issue require an attacker to have access to a virtual machine with 3D graphics enabled. It is not enabled by default on ESXi and is enabled by default on Workstation and Fusion.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2019-0019.html");
  script_set_attribute(attribute:"solution", value:
"Update to VMware Fusion version 11.5.0, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5536");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "installed_sw/VMware Fusion");

  exit(0);
}

include('vcf.inc');


app_info = vcf::get_app_info(app:'VMware Fusion');

constraints = [
  { 'fixed_version' : '11.5.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
