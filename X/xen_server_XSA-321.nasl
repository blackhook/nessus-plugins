##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(138363);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/28");

  script_cve_id("CVE-2020-15565");
  script_xref(name:"IAVB", value:"2020-B-0034-S");

  script_name(english:"Xen Insufficient Cache Write-Back (XSA-321)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor installed on the remote host is affected by a denial
of service and potential privilege escalation due to an insufficient cache write-back under VT-d. A malicious guest may
be able to retain read/write DMA access to frames returned to Xen's free pool, and later reused to access sensitive 
information pertaining to other guests to crash the host, resulting in a denial of service and privilege escalation.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://xenbits.xen.org/xsa/advisory-321.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a845e3fe");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch or workaround according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15565");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("xen_server_detect.nbin");
  script_require_keys("installed_sw/Xen Hypervisor", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');


app = 'Xen Hypervisor';

app_info = vcf::xen_hypervisor::get_app_info(app:app);

if (report_paranoia < 2) audit(AUDIT_PARANOID);
fixes['4.9']['fixed_ver']           = '4.9.4';
fixes['4.9']['fixed_ver_display']   = '4.9.4 (changeset a852040)';
fixes['4.9']['affected_ver_regex']  = "^4\.9\.";
fixes['4.9']['affected_changesets'] = make_list('3c9a984', '46d6a07',
  '8391701', '1c51a29', '7338b33', '6fe2c30', '6ee71c9', '098d959', 
  '7154530', '6e477c2', '6a1c431', '41f597f', '1eae172', 'f1e75e5', 
  'f034ab4', '9737f89', '1dd6478', '80d78ac', 'ad0c1a0', '04af886', 
  '93cc305', '45c9073', '773686b', '4e79375', '8d26adc', 'b3718b7', 
  'cf2e9cc', '43ab30b', '55bd90d', '173e805', '248f22e', 'ec229c2', 
  'e879bfe', 'ce126c9', '4b69427', '8d1ee9f', 'e60b3a9', '25f5530', 
  '49db55f', 'fa34ed5', '704f7ec', 'a930a74', '8c52ee2', '2e15a19', 
  '70639ac', 'c3b479d', 'e349eae', '632fb4e', '4608c6d', '7daacca', 
  '859e48e', '5be2dd0', 'b0147bd', 'cadd66a', 'd3c4b60', 'd59f5c4', 
  '44303c6', '79538ba', '80c3157', '73f1a55', 'bc20fb1', '754a531', 
  '7b032c2', 'ff4fdf0', '8d2a688', 'b9013d7', 'bc8e5ec', '34907f5', 
  'e70bf7e', 'fa0b891', '3a8177c', '04ec835', '8d63ec4', '1ff6b4d', 
  'f092d86', 'e4b534f', '87c49fe', '19becb8', '43775c0', 'f6b0f33', 
  'a17e75c', '67530e7', 'f804549', '84f81a8', '56aa239', '105db42', 
  'd9da3ea', 'ac90240', '3db28b0', '9b6f1c0', '0c4bbad', '917d8d3', 
  '3384ea4', '352421f', '04e9dcb', '1612f15', 'f952b1d', '63d9330', 
  'f72414a', 'ac3a5f8', '1ae6b8e', '1dd3dcc', '7390fa1', '7e78dc4', 
  '8fdfb1e', '55d36e2', '045f37c', 'dd7e637', '7a40b5b', 'f5acf97');

fixes['4.10']['fixed_ver']           = '4.10.4';
fixes['4.10']['fixed_ver_display']   = '4.10.4 (changeset 4418841)';
fixes['4.10']['affected_ver_regex']  = "^4\.10\.";
fixes['4.10']['affected_changesets'] = make_list('d9c67d3', '8976bab',
  '388e303', '0b0a155', '9df4399', 'fd57038', 'a9bda69', 'a380168', 
  'c1a4914', '6261a06', 'fd6e49e', 'bd20589', 'ce05683', '934d6e1', 
  '6e636f2', 'dfc0b23', '2f83654', 'bf467cc', '6df4d40', 'e20bb58', 
  'a1a9b05', 'afca67f', 'b922c44', 'b413732', '3d60903', 'b01c84e', 
  '1e722e6', '59cf3a0', 'fabfce8', 'a4dd2fe', '6e63a6f', '24d62e1', 
  'cbedabf', '38e589d', 'a91b8fc', '3e0c316', '49a5d6e', '6cb1cb9', 
  'ba2776a', '9d143e8', 'fe8dab3', '07e546e', 'fefa5f9', 'c9f9ff7', 
  '406d40d', 'e489955', '37139f1', 'fde09cb', '804ba02', 'e8c3971', 
  'a8c4293', 'aa40452', '1da3dab', 'e5632c4', '902e72d', '6a14610', 
  'ea815b2', '13ad331', '61b75d9', 'e70e7bf', 'e966e2e', 'dfa16a1', 
  'a71e199', 'c98be9e', 'a548e10', 'd3c0e84', '53b1572', '7203f9a', 
  '6d1659d', 'a782173', '24e90db', '0824bc6', 'e6f3135', '3131bf9');

fixes['4.11']['fixed_ver']           = '4.11.4';
fixes['4.11']['fixed_ver_display']   = '4.11.4 (changeset e6ddf4a)';
fixes['4.11']['affected_ver_regex']  = "^4\.11\.";
fixes['4.11']['affected_changesets'] = make_list('f2bc74c', 'd623658',
  '37c853a', '8bf72ea', '2d11e6d', '4ed0007', '7def72c', '18be3aa', 
  'a3a392e', 'e96cdba', '2b77729', '9be7992', 'b8d476a', '1c751c4', 
  '7dd2ac3', 'a58bba2', '7d8fa6a', '4777208', '48e8564', '2efca7e', 
  'afe82f5', 'e84b634', '96a8b5b');

fixes['4.12']['fixed_ver']           = '4.12.4';
fixes['4.12']['fixed_ver_display']   = '4.12.4-pre (changeset d96c0f1)';
fixes['4.12']['affected_ver_regex']  = "^4\.12\.";
fixes['4.12']['affected_changesets'] = make_list('653811e', '26072a5',
  'b292255', '38dc269', '5733de6', 'd69f305', '8faa45e', '731bdaf', 
  'ec57b9a', 'a634229', '050fe48', '436ec68', '96e8aba', '7cdc0cf', 
  'd937532', '7641573', '7eed533', '74a1230', '946113a', '6182e5d', 
  'ad20170', '218a19b', 'aca68b9', '1f581f9', '4969f34', 'ed44947', 
  '2eb277e', 'b3af150', 'f769c99', 'bcdaffc', '2b10a32', 'a022f36', 
  'dd49ddf', 'bc775d0', 'be5c240');

fixes['4.13']['fixed_ver']           = '4.13.2';
fixes['4.13']['fixed_ver_display']   = '4.13.2-pre (changeset 572e349)';
fixes['4.13']['affected_ver_regex']  = "^4\.13\.";
fixes['4.13']['affected_changesets'] = make_list('0c8c10d', '493e143',
  '8b9be8f', 'f1055a2', '005d5ea', '1c7a98c', '2b34d8c', '56e117f', 
  '7a76deb', '3e41b72', '9f7e8ba', 'cdd8f95', 'a9d46ba', '05ba427', 
  '780d376', '31c5d84', '27d4f1a', '11ea967', '53bafb5', 'b4afe05', 
  '74ce65c', '0243559', '8ad99de', 'ea7e8d2', '350aaca', 'c3eea2c', 
  '0523225', '672976c', 'a6f2080', 'c437e06', '0a85f84', '85ac008', 
  '7f6b66d', '04aedf4', 'f2ad77b', 'd61fef6', 'eccc242', '6bfb364', 
  'bdddd33', '7d57caa', 'd74eb10', '9eec3ee', 'd112db3', '333519f');

fixes['4.14']['fixed_ver']           = '4.14.0';
fixes['4.14']['fixed_ver_display']   = '4.14.0-rc (changeset c23274f)';
fixes['4.14']['affected_ver_regex']  = "^4\.14\.";
fixes['4.14']['affected_changesets'] = make_list('a64ea16', '23570bc',
  'b6d9398', '91526b4', '6229882', '5fe515a', 'bc3d9f9', '1104288', 
  '23a216f', '2e9c2bc', 'f97f99c', '158912a', 'd44cbbe', 'be63d9d', 
  '5b718d2', '0dbed3a', '5b13eb1', '3b7dab9', '23ca7ec', '0e2e549', 
  'da53345', 'd476440', '88cfd06', '92167e9', 'bcdfbb7', '40b532f', 
  'd20c0f1', '620225c', 'bfb310e', 'ace450e', '2b1a218', '20b65c1', 
  'fbdf181', '01b9a28', '2c8ac47', 'ed69c2e', '3471caf', 'f91d103', 
  'd3688bf', 'e4d2207', 'f325d24', 'fde76f8', '4f4f6a6', 'b67e859', 
  '81ebf6e', 'f1d376a', 'f0dca89', '25636ed', '71ca0e0', 'fde4acd', 
  '54463aa', '1accd92', '057012d', 'f79cd47', '585c7f4', 'c22ced9', 
  '700738b', '3625b04', 'd3db7e0', '05f488e', '3371ced', '1251402', 
  'fec6a7a', 'b91825f', '2995d0a', '6fa25d5', '3664f7b', 'b87dd7b', 
  '10ea4e4', 'aad20e5', '7028534', 'ceaae74', '6a49b9a', 'caab85a', 
  '058023b', '30a72f0', '1a58d8d', '31a714d', 'f7039ee', '1fe4066', 
  '985ba41', '835d8d6', '63b4c9b', '16c36d2', '03dc5f0', '11ba5cd', 
  '726c78d', '75131ad');


vcf::xen_hypervisor::check_version_and_report(app_info:app_info, fixes:fixes, severity:SECURITY_WARNING);