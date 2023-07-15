##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144975);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-25597");
  script_xref(name:"IAVB", value:"2020-B-0056-S");

  script_name(english:"Xen mishandling of the event channel validity constraint DoS (XSA-338))");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Xen due to a mishandling of the constraint that once-valid event 
channels may not turn invalid. An unprivileged guest may be able to crash Xen, leading to a denial of service for 
the entire system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-338.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch or workaround according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25597");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/14");

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

fixes['4.10']['fixed_ver']           = '4.10.4';
fixes['4.10']['fixed_ver_display']   = '4.10.4 (changeset f85223f)';
fixes['4.10']['affected_ver_regex']  = "^4\.10\.";
fixes['4.10']['affected_changesets'] = make_list('635ae12', '3d14937',
  '4218b74', '93be943', '4418841', 'd9c67d3', '8976bab', '388e303', 
  '0b0a155', '9df4399', 'fd57038', 'a9bda69', 'a380168', 'c1a4914', 
  '6261a06', 'fd6e49e', 'bd20589', 'ce05683', '934d6e1', '6e636f2', 
  'dfc0b23', '2f83654', 'bf467cc', '6df4d40', 'e20bb58', 'a1a9b05', 
  'afca67f', 'b922c44', 'b413732', '3d60903', 'b01c84e', '1e722e6', 
  '59cf3a0', 'fabfce8', 'a4dd2fe', '6e63a6f', '24d62e1', 'cbedabf', 
  '38e589d', 'a91b8fc', '3e0c316', '49a5d6e', '6cb1cb9', 'ba2776a', 
  '9d143e8', 'fe8dab3', '07e546e', 'fefa5f9', 'c9f9ff7', '406d40d', 
  'e489955', '37139f1', 'fde09cb', '804ba02', 'e8c3971', 'a8c4293', 
  'aa40452', '1da3dab', 'e5632c4', '902e72d', '6a14610', 'ea815b2', 
  '13ad331', '61b75d9', 'e70e7bf', 'e966e2e', 'dfa16a1', 'a71e199', 
  'c98be9e', 'a548e10', 'd3c0e84', '53b1572', '7203f9a', '6d1659d', 
  'a782173', '24e90db', '0824bc6', 'e6f3135', '3131bf9');

fixes['4.11']['fixed_ver']           = '4.11.4';
fixes['4.11']['fixed_ver_display']   = '4.11.4 (changeset 7284bfa)';
fixes['4.11']['affected_ver_regex']  = "^4\.11\.";
fixes['4.11']['affected_changesets'] = make_list('2fe163d', '2031bd3',
  '7bf4983', '7129b9e', 'ddaaccb', 'e6ddf4a', 'f2bc74c', 'd623658', 
  '37c853a', '8bf72ea', '2d11e6d', '4ed0007', '7def72c', '18be3aa', 
  'a3a392e', 'e96cdba', '2b77729', '9be7992', 'b8d476a', '1c751c4', 
  '7dd2ac3', 'a58bba2', '7d8fa6a', '4777208', '48e8564', '2efca7e', 
  'afe82f5', 'e84b634', '96a8b5b');

fixes['4.12']['fixed_ver']           = '4.12.4';
fixes['4.12']['fixed_ver_display']   = '4.12.4-pre (changeset b2db007)';
fixes['4.12']['affected_ver_regex']  = "^4\.12\.";
fixes['4.12']['affected_changesets'] = make_list('1dfd2e2', '76a0760',
  'd28c52e', '8b8fff2', '320e7a7', '0446e3d', 'a81e655', 'caebaf3', 
  '76d9349', '81564c4', 'ff79981', '3186568', '40e0cf8', 'fbf016f', 
  '8c1c3e7', '5bd49ca', 'e0bd899', 'c481b9f', '1336ca1', 'dca9cc7', 
  '07fd5d3', '85ce36d', 'df9a0ad', '7cce3f2', '43258ce', 'a1aae54', 
  'df11056', '19e0bbb', 'd96c0f1', '653811e', '26072a5', 'b292255', 
  '38dc269', '5733de6', 'd69f305', '8faa45e', '731bdaf', 'ec57b9a', 
  'a634229', '050fe48', '436ec68', '96e8aba', '7cdc0cf', 'd937532', 
  '7641573', '7eed533', '74a1230', '946113a', '6182e5d', 'ad20170', 
  '218a19b', 'aca68b9', '1f581f9', '4969f34', 'ed44947', '2eb277e', 
  'b3af150', 'f769c99', 'bcdaffc', '2b10a32', 'a022f36', 'dd49ddf', 
  'bc775d0', 'be5c240');

fixes['4.13']['fixed_ver']           = '4.13.2';
fixes['4.13']['fixed_ver_display']   = '4.13.2-pre (changeset ae922b9)';
fixes['4.13']['affected_ver_regex']  = "^4\.13\.";
fixes['4.13']['affected_changesets'] = make_list('f27980a', 'b7fcbe0',
  '42fcdd4', '286b353', 'b980319', 'aa1d9a7', 'bd63ab5', '4fb1ad7', 
  '4a0c174', '6ef4dad', 'c663fa5', '761e8df', '6469039', 'b908343', 
  'ac4ec48', 'a7f0434', '0861885', '9b367b2', 'e182965', 'befa216', 
  'e9e72fb', 'b67bb90', 'fff1874', 'ec972cb', 'd967a2b', '665f5c1', 
  'ddb6fd3', '378321b', '572e349', '0c8c10d', '493e143', '8b9be8f', 
  'f1055a2', '005d5ea', '1c7a98c', '2b34d8c', '56e117f', '7a76deb', 
  '3e41b72', '9f7e8ba', 'cdd8f95', 'a9d46ba', '05ba427', '780d376', 
  '31c5d84', '27d4f1a', '11ea967', '53bafb5', 'b4afe05', '74ce65c', 
  '0243559', '8ad99de', 'ea7e8d2', '350aaca', 'c3eea2c', '0523225', 
  '672976c', 'a6f2080', 'c437e06', '0a85f84', '85ac008', '7f6b66d', 
  '04aedf4', 'f2ad77b', 'd61fef6', 'eccc242', '6bfb364', 'bdddd33', 
  '7d57caa', 'd74eb10', '9eec3ee', 'd112db3', '333519f');

fixes['4.14']['fixed_ver']           = '4.14.1';
fixes['4.14']['fixed_ver_display']   = '4.14.1-pre (changeset e417504)';
fixes['4.14']['affected_ver_regex']  = "^4\.14\.";
fixes['4.14']['affected_changesets'] = make_list('0bc4177', '5ad3152',
  'fc8200a', '5eab5f0', 'b04d673', '28855eb', '174be04', '158c3bd', 
  '3535f23', 'de7e543', '483b43c', '431d52a', 'ceafff7', '369e7a3', 
  '98aa6ea', '80dec06', '5482c28', 'edf5b86', 'eca6d5e', 'c3a0fc2', 
  '864d570', 'afed8e4', 'a5dab0a', 'b8c3e33', 'f836759');

vcf::xen_hypervisor::check_version_and_report(app_info:app_info, fixes:fixes, severity:SECURITY_WARNING);