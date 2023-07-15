#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156325);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id("CVE-2021-28710");
  script_xref(name:"IAVB", value:"2021-B-0068-S");

  script_name(english:"Xen Certain VT-d IOMMUs May Not Work In Shared Page Table Mode (XSA-390)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor installed on the remote host is affected by a
vulnerability in the IOMMU that fails to strip tables in shared page table mode. The vulnerability only affects x86 
Intel systems. A local, authorized attacker could use this vulnerability to escalate from guest to host privilages.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-390.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28710");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("xen_server_detect.nbin");
  script_require_keys("installed_sw/Xen Hypervisor", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var fixes;
var app = 'Xen Hypervisor';
var app_info = vcf::xen_hypervisor::get_app_info(app:app);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixes['4.15']['fixed_ver']           = '4.15.2';
fixes['4.15']['fixed_ver_display']   = '4.15.2-pre (changeset 963ab60)';
fixes['4.15']['affected_ver_regex']  = "^4\.15([^0-9]|$)";
fixes['4.15']['affected_changesets'] = make_list('2a19ee2', '2fb9c59',
  '567a8e9', '03b2a59', '541ae91', 'c61cd82', '751efc5', 'cae4b7b',
  'b033a41', 'e8a4448', 'd23e96e', '93f9c29', '7eaf2a3', 'f90cea9',
  'f50ef17', 'b79615b', 'ad70a24', 'a2a17ee', 'd4f39cf', 'a82a0a8',
  '0950b18', 'c67f652', 'c3c9a7c', '8f5a16c', 'b482e96', 'cb7d7aa',
  '932ff43', 'c554188', '05df87b', '7799c8a');

vcf::xen_hypervisor::check_version_and_report(app_info:app_info, fixes:fixes, severity:SECURITY_WARNING);
