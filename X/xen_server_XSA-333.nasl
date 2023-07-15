##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144862);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-25602");
  script_xref(name:"IAVB", value:"2020-B-0056-S");

  script_name(english:"Xen missing error handling in MSR_MISC_ENABLE DoS (XSA-333)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Xen server due to missing error handling in MISC_ENABLE MSR. 
A malicious PV guest administrator can trigger Xen to crash, resulting in a host DoS.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://xenbits.xen.org/xsa/advisory-333.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d963cab");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch or workaround according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25602");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(755);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
fixes['4.11']['fixed_ver_display']   = '4.11.4 (changeset 7129b9e)';
fixes['4.11']['affected_ver_regex']  = "^4\.11\.";
fixes['4.11']['affected_changesets'] = make_list('ddaaccb', 'e6ddf4a',
  'f2bc74c', 'd623658', '37c853a', '8bf72ea', '2d11e6d', '4ed0007', 
  '7def72c', '18be3aa', 'a3a392e', 'e96cdba', '2b77729', '9be7992', 
  'b8d476a', '1c751c4', '7dd2ac3', 'a58bba2', '7d8fa6a', '4777208', 
  '48e8564', '2efca7e', 'afe82f5', 'e84b634', '96a8b5b');

fixes['4.12']['fixed_ver']           = '4.12.4';
fixes['4.12']['fixed_ver_display']   = '4.12.4-pre (changeset 320e7a7)';
fixes['4.12']['affected_ver_regex']  = "^4\.12\.";
fixes['4.12']['affected_changesets'] = make_list('0446e3d', 'a81e655',
  'caebaf3', '76d9349', '81564c4', 'ff79981', '3186568', '40e0cf8', 
  'fbf016f', '8c1c3e7', '5bd49ca', 'e0bd899', 'c481b9f', '1336ca1', 
  'dca9cc7', '07fd5d3', '85ce36d', 'df9a0ad', '7cce3f2', '43258ce', 
  'a1aae54', 'df11056', '19e0bbb', 'd96c0f1', '653811e', '26072a5', 
  'b292255', '38dc269', '5733de6', 'd69f305', '8faa45e', '731bdaf', 
  'ec57b9a', 'a634229', '050fe48', '436ec68', '96e8aba', '7cdc0cf', 
  'd937532', '7641573', '7eed533', '74a1230', '946113a', '6182e5d', 
  'ad20170', '218a19b', 'aca68b9', '1f581f9', '4969f34', 'ed44947', 
  '2eb277e', 'b3af150', 'f769c99', 'bcdaffc', '2b10a32', 'a022f36', 
  'dd49ddf', 'bc775d0', 'be5c240');

fixes['4.13']['fixed_ver']           = '4.13.2';
fixes['4.13']['fixed_ver_display']   = '4.13.2-pre (changeset b980319)';
fixes['4.13']['affected_ver_regex']  = "^4\.13\.";
fixes['4.13']['affected_changesets'] = make_list('aa1d9a7', 'bd63ab5',
  '4fb1ad7', '4a0c174', '6ef4dad', 'c663fa5', '761e8df', '6469039', 
  'b908343', 'ac4ec48', 'a7f0434', '0861885', '9b367b2', 'e182965', 
  'befa216', 'e9e72fb', 'b67bb90', 'fff1874', 'ec972cb', 'd967a2b', 
  '665f5c1', 'ddb6fd3', '378321b', '572e349', '0c8c10d', '493e143', 
  '8b9be8f', 'f1055a2', '005d5ea', '1c7a98c', '2b34d8c', '56e117f', 
  '7a76deb', '3e41b72', '9f7e8ba', 'cdd8f95', 'a9d46ba', '05ba427', 
  '780d376', '31c5d84', '27d4f1a', '11ea967', '53bafb5', 'b4afe05', 
  '74ce65c', '0243559', '8ad99de', 'ea7e8d2', '350aaca', 'c3eea2c', 
  '0523225', '672976c', 'a6f2080', 'c437e06', '0a85f84', '85ac008', 
  '7f6b66d', '04aedf4', 'f2ad77b', 'd61fef6', 'eccc242', '6bfb364', 
  'bdddd33', '7d57caa', 'd74eb10', '9eec3ee', 'd112db3', '333519f');

fixes['4.14']['fixed_ver']           = '4.14.1';
fixes['4.14']['fixed_ver_display']   = '4.14.1-pre (changeset b04d673)';
fixes['4.14']['affected_ver_regex']  = "^4\.14\.";
fixes['4.14']['affected_changesets'] = make_list('28855eb', '174be04',
  '158c3bd', '3535f23', 'de7e543', '483b43c', '431d52a', 'ceafff7', 
  '369e7a3', '98aa6ea', '80dec06', '5482c28', 'edf5b86', 'eca6d5e', 
  'c3a0fc2', '864d570', 'afed8e4', 'a5dab0a', 'b8c3e33', 'f836759');

vcf::xen_hypervisor::check_version_and_report(app_info:app_info, fixes:fixes, severity:SECURITY_WARNING);