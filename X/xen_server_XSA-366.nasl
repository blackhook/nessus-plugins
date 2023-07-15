##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148843);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-27379");
  script_xref(name:"IAVB", value:"2021-B-0011-S");

  script_name(english:"Xen Missed Flush DoS or Privilege Escalation (XSA-366)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor installed on the remote host is affected by an issue
allowing x86 Intel HVM guest OS users to achieve unintended read/write DMA access, and possibly cause a denial of
service (host OS crash) or gain privileges. This occurs because a backport missed a flush, and thus IOMMU updates were
not always correct. NOTE: this issue exists because of an incomplete fix for CVE-2020-15565.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-366.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27379");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

app = 'Xen Hypervisor';
app_info = vcf::xen_hypervisor::get_app_info(app:app);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixes['4.11']['fixed_ver']           = '4.11.4';
fixes['4.11']['fixed_ver_display']   = '4.11.4 (changeset 76d369d)';
fixes['4.11']['affected_ver_regex']  = "^4\.11\.";
fixes['4.11']['affected_changesets'] = make_list('80cad58', '1c7d984',
  'f9090d9', '310ab79', '2d49825', '24f7d03', 'f1f3dee', '1e87058',
  '4cc2387', '4053771', 'b3f4121', 'e36f81f', '1034a45', '7791d2e',
  '5724431', '495e973', '771a105', 'b3f80a3', '966f266', '57261ac',
  '1b7ed67', '0a6bbf9', '6be47ee', '2fe5a55', '36621b7', '88f6ff5',
  '170445f', '550387f', '0297770', 'd2b6bf9', '41a822c', '8ab4af9',
  '4fe1326', '4438fc1', '2a730d5', '62aed78', '1447d44', '3b5de11',
  '65fad0a', 'b5eb495', 'e274c8b', '1d021db', '63199df', '7739ffd',
  '4f35f7f', '490c517', '7912bbe', 'f5ec9f2', 'ad7d040', '3630a36',
  '3263f25', '3e565a9', '30b3f29', '3def846', 'cc1561a', '6e9de08',
  '13f60bf', '9703a2f', '7284bfa', '2fe163d', '2031bd3', '7bf4983',
  '7129b9e', 'ddaaccb', 'e6ddf4a', 'f2bc74c', 'd623658', '37c853a',
  '8bf72ea', '2d11e6d', '4ed0007', '7def72c', '18be3aa', 'a3a392e',
  'e96cdba', '2b77729', '9be7992', 'b8d476a', '1c751c4', '7dd2ac3',
  'a58bba2', '7d8fa6a', '4777208', '48e8564', '2efca7e', 'afe82f5',
  'e84b634', '96a8b5b');

vcf::xen_hypervisor::check_version_and_report(app_info:app_info, fixes:fixes, severity:SECURITY_WARNING);
