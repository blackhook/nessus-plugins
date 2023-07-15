#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119099);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/20");

  script_cve_id("CVE-2018-6983");
  script_bugtraq_id(105986);
  script_xref(name:"VMSA", value:"2018-0030");

  script_name(english:"VMware Fusion 10.x < 10.1.5 / 11.x < 11.0.2 Virtual Network Integer Overflow Vulnerability (VMSA-2018-0030) (macOS)");
  script_summary(english:"Checks the VMware Fusion version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote macOS or Mac OS X
host is affected by an integer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Fusion installed on the remote macOS or
Mac OS X host is 10.x prior to 10.1.5 or 11.x prior to 11.0.2. It is,
therefore, affected by integer overflow vulnerability in the
virtual network devices. An attacker with access to a guest 
system may be able to execute code on the host system by
leveraging this vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0030.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Fusion version 10.1.5, 11.0.2, or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6983");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "installed_sw/VMware Fusion");

  exit(0);
}

include("vcf.inc");

app_info = vcf::get_app_info(app:"VMware Fusion");
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "min_version" : "10", "fixed_version" : "10.1.5" },
  { "min_version" : "11", "fixed_version" : "11.0.2" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
