#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(152209);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-28693");
  script_xref(name:"IAVB", value:"2021-B-0044-S");

  script_name(english:"Xen / ARM Boot Modules Are Not Scrubbed Information Exposure (XSA-372)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor installed on the remote host is affected by an
information disclosure vulnerability as boot modules are not scrubbed. The bootloader will load boot modules (e.g.
  kernel, initramfs...) in a temporary area before they are copied by Xen to each domain memory. To ensure sensitive
data is not leaked from the modules, Xen must 'scrub' them before handing the page over to the allocator. Unfortunately,
it was discovered that modules will not be scrubbed on Arm.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xenproject.org/xsa/advisory-372.txt");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28693");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/04");

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

app = 'Xen Hypervisor';
app_info = vcf::xen_hypervisor::get_app_info(app:app);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixes['4.12']['fixed_ver']           = '4.12.4';
fixes['4.12']['fixed_ver_display']   = '4.12.4 (changeset aa8866c)';
fixes['4.12']['affected_ver_regex']  = "^4\.12\.";
fixes['4.12']['affected_changesets'] = make_list('2c39570', '5984905',
  '5b280a5', '955c604', 'cd5666c', '1df73ab', 'b406997', 'f66542f',
  '26764c5', 'b100d3e', '17db0ba', '2e9e9e4', '652a259', 'b8737d2',
  '70c53ea', '4cf5929', '8d26cdd', 'f1f3226', 'cce7cbd', '2525a74',
  'c8b97ff', '2186c16', '51e9505', '4943ea7', '3c13a87', 'd4b884b',
  '7da9325', 'd6d3b13', '9fe89e1', 'd009b8d', '674108e', 'bfda5ae',
  '551d75d', '5e1bac4', 'f8443e8', '655190d', 'f860f42', '9f73020',
  'aeebc0c', 'f1a4126', 'b1efedb', '4739f79', '0dbcdcc', '444b717',
  '544a775', 'c64ff3b', '8145d38', '14f577b', '40ab019', '1dd870e',
  '5c15a1c', '6602544', '14c9c0f', 'dee5d47', '7b2f479', '46ad884',
  'eaafa72', '0e6975b', '8e0c2a2', '51eca39', '7ae2afb', '5e11fd5',
  '34056b2', 'fd4cc0b', '4f9294d', '97b7b55');

fixes['4.13']['fixed_ver']           = '4.13.4';
fixes['4.13']['fixed_ver_display']   = '4.13.4-pre (changeset def4352)';
fixes['4.13']['affected_ver_regex']  = "^4\.13\.";
fixes['4.13']['affected_changesets'] = make_list('95197d4', 'ef8b235',
  'f17d848', 'fa5afbb', '4d54414', '287f229', 'e289ed6', '2841329',
  '33049e3', '53f4ce9', '8113b02', '0e711a0', '21e1ae3', '4352a49',
  'e93d278', '231237c', 'ca06bce', '5aef2c5', '5de1558', 'e3bcd4d');

fixes['4.14']['fixed_ver']           = '4.14.3';
fixes['4.14']['fixed_ver_display']   = '4.14.3-pre (changeset 7053c8e)';
fixes['4.14']['affected_ver_regex']  = "^4\.14\.";
fixes['4.14']['affected_changesets'] = make_list('5caa690', 'b046e05',
  '3f85493', 'ac507e0', 'ebfdf0c', '9d963a7', 'b15c24a', 'f23cb47',
  'c2f78b4', 'a351751');

fixes['4.15']['fixed_ver']           = '4.15.1';
fixes['4.15']['fixed_ver_display']   = '4.15.1-pre (changeset 7044184)';
fixes['4.15']['affected_ver_regex']  = "^4\.15\.";
fixes['4.15']['affected_changesets'] = make_list('0a64b18', 'eae0dfa',
  '89c6e84', '7c3c984', '6a7e21a', 'ee2b1d6', 'edeaa04', 'cacad0c',
  '3e6c1b6', '78a7c3b', '280d472', 'eb1f325', 'dfcce09', 'c129b5f',
  'e2e80ff', '5788a7e', 'bb071ce', '92dd3b5', 'baa6957', 'c86d8ec', 'e72bf72');

vcf::xen_hypervisor::check_version_and_report(app_info:app_info, fixes:fixes, severity:SECURITY_NOTE);
