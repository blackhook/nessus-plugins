##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144755);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-29480");
  script_xref(name:"IAVB", value:"2020-B-0077-S");

  script_name(english:"Xen xenstore watch notification Information Disclosure (XSA-115)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor installed on the remote host is affected by an
information disclosure vulnerability due to a lack of permission checks for xenstore watch event reporting. A guest
administrator can watch the root xenstored node, which will cause notifications for every created, modified, and deleted
key. A guest administrator can also use the special watches, which will cause a notification every time a domain is
created and destroyed. Data may include: number, type, and domids of other VMs; existence and domids of driver domains;
numbers of virtual interfaces, block devices, vcpus; existence of virtual framebuffers and their backend style (e.g.,
existence of VNC service); Xen VM UUIDs for other domains; timing information about domain creation and device setup;
and some hints at the backend provisioning of VMs and their devices. The watch events do not contain values stored in
xenstore, only key names. A guest administrator can observe non-sensitive domain and device lifecycle events relating to
other guests. This information allows some insight into overall system configuration (including the number and general
nature of other guests), and configuration of other guests (including the number and general nature of other guests'
devices). This information might be commercially interesting or might make other attacks easier. There is not believed
to be exposure of sensitive data. Specifically, there is no exposure of VNC passwords, port numbers, pathnames in host
and guest filesystems, cryptographic keys, or within-guest data.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-115.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch or workaround according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-29480");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'Xen Hypervisor';

app_info = vcf::xen_hypervisor::get_app_info(app:app);

fixes['4.10']['fixed_ver']           = '4.10.4';
fixes['4.10']['fixed_ver_display']   = '4.10.4 (changeset e644edc)';
fixes['4.10']['affected_ver_regex']  = "^4\.10\.";
fixes['4.10']['affected_changesets'] = make_list('7e16a0e', 'a4c2c94',
  'bdd36b6', '59dc712', '57a55a4', '03937f9', 'f06e4ac', '3658044',
  '9edd614', '8cb4d2d', '2fee46c', '06092d1', '77d6b2b', 'a043a64',
  '3afd384', 'e8231b6', '1d72d99', '8eb5328', 'f79f47f', 'f91d2a9',
  '1fdcfdb', '17ec9b4', '15b2980', '398f91c', '5114e77', '7a4ec79',
  '78d903e', '2012db4', '71da63b', '56f8da7', 'd73e972', '6f012ec',
  '75a05da', 'c334b87', '07ad8ff', '1719f79', 'f58caa4', 'f2befb6',
  '83b7f04', 'e081568', '7f0793a', '8fac37e', 'baf80b6', '5402540',
  'f85223f', '635ae12', '3d14937', '4218b74', '93be943', '4418841',
  'd9c67d3', '8976bab', '388e303', '0b0a155', '9df4399', 'fd57038',
  'a9bda69', 'a380168', 'c1a4914', '6261a06', 'fd6e49e', 'bd20589',
  'ce05683', '934d6e1', '6e636f2', 'dfc0b23', '2f83654', 'bf467cc',
  '6df4d40', 'e20bb58', 'a1a9b05', 'afca67f', 'b922c44', 'b413732',
  '3d60903', 'b01c84e', '1e722e6', '59cf3a0', 'fabfce8', 'a4dd2fe',
  '6e63a6f', '24d62e1', 'cbedabf', '38e589d', 'a91b8fc', '3e0c316',
  '49a5d6e', '6cb1cb9', 'ba2776a', '9d143e8', 'fe8dab3', '07e546e',
  'fefa5f9', 'c9f9ff7', '406d40d', 'e489955', '37139f1', 'fde09cb',
  '804ba02', 'e8c3971', 'a8c4293', 'aa40452', '1da3dab', 'e5632c4',
  '902e72d', '6a14610', 'ea815b2', '13ad331', '61b75d9', 'e70e7bf',
  'e966e2e', 'dfa16a1', 'a71e199', 'c98be9e', 'a548e10', 'd3c0e84',
  '53b1572', '7203f9a', '6d1659d', 'a782173', '24e90db', '0824bc6',
  'e6f3135', '3131bf9');

fixes['4.11']['fixed_ver']           = '4.11.4';
fixes['4.11']['fixed_ver_display']   = '4.11.4 (changeset 7791d2e)';
fixes['4.11']['affected_ver_regex']  = "^4\.11\.";
fixes['4.11']['affected_changesets'] = make_list('5724431', '495e973',
  '771a105', 'b3f80a3', '966f266', '57261ac', '1b7ed67', '0a6bbf9',
  '6be47ee', '2fe5a55', '36621b7', '88f6ff5', '170445f', '550387f',
  '0297770', 'd2b6bf9', '41a822c', '8ab4af9', '4fe1326', '4438fc1',
  '2a730d5', '62aed78', '1447d44', '3b5de11', '65fad0a', 'b5eb495',
  'e274c8b', '1d021db', '63199df', '7739ffd', '4f35f7f', '490c517',
  '7912bbe', 'f5ec9f2', 'ad7d040', '3630a36', '3263f25', '3e565a9',
  '30b3f29', '3def846', 'cc1561a', '6e9de08', '13f60bf', '9703a2f',
  '7284bfa', '2fe163d', '2031bd3', '7bf4983', '7129b9e', 'ddaaccb',
  'e6ddf4a', 'f2bc74c', 'd623658', '37c853a', '8bf72ea', '2d11e6d',
  '4ed0007', '7def72c', '18be3aa', 'a3a392e', 'e96cdba', '2b77729',
  '9be7992', 'b8d476a', '1c751c4', '7dd2ac3', 'a58bba2', '7d8fa6a',
  '4777208', '48e8564', '2efca7e', 'afe82f5', 'e84b634', '96a8b5b');

fixes['4.12']['fixed_ver']           = '4.12.4';
fixes['4.12']['fixed_ver_display']   = '4.12.4 (changeset d009b8d)';
fixes['4.12']['affected_ver_regex']  = "^4\.12\.";
fixes['4.12']['affected_changesets'] = make_list('674108e', 'bfda5ae',
  '551d75d', '5e1bac4', 'f8443e8', '655190d', 'f860f42', '9f73020',
  'aeebc0c', 'f1a4126', 'b1efedb', '4739f79', '0dbcdcc', '444b717',
  '544a775', 'c64ff3b', '8145d38', '14f577b', '40ab019', '1dd870e',
  '5c15a1c', '6602544', '14c9c0f', 'dee5d47', '7b2f479', '46ad884',
  'eaafa72', '0e6975b', '8e0c2a2', '51eca39', '7ae2afb', '5e11fd5',
  '34056b2', 'fd4cc0b', '4f9294d', '97b7b55');

fixes['4.13']['fixed_ver']           = '4.13.3';
fixes['4.13']['fixed_ver_display']   = '4.13.3-pre (changeset 4056c3e)';
fixes['4.13']['affected_ver_regex']  = "^4\.13\.";
fixes['4.13']['affected_changesets'] = make_list('f4d84a2', '65c187f',
  '2df79ff', 'b693968', '52a0a8f', '60e3727', '8cc0a86', 'ef765f6',
  'b8f23da', 'ee416da', '1819c9d', '1ab192f', '2007c63', '2948458',
  '4959626', '2fa586c', 'b530227', '74c5729', 'a1d8a6c', 'd064b65',
  '4f30743', '72031bc', '7d6f52d', 'ec09215');

fixes['4.14']['fixed_ver']           = '4.14.1';
fixes['4.14']['fixed_ver_display']   = '4.14.1-pre (changeset 61d3863)';
fixes['4.14']['affected_ver_regex']  = "^4\.14\.";
fixes['4.14']['affected_changesets'] = make_list('9e53440', '335ef5b',
  '6fa3e05', 'f4405b6', '228e562', '0a79a1b', '5073c6b', '5259358',
  '3d0e1a1', '117521e', '91992c7', '4e298fa', '3beffb3', 'da67712',
  '9c898a8', 'f130d5f', '1d1d1f5', '72bd989', '8e6c236', '1cfb9b1',
  '7c6ee4e', 'd11d977', '1ad1773', '0057b1f', 'd101b41', 'd95f450',
  '73a0927', 'a38060e', '78a53f0', '89ae1b1', '7398a44', '59b8366',
  '1f9f1cb', 'f728b2d', '71a12a9', '0c96e42', '29b48aa', 'd131310',
  '7d2b21f', 'f61c5d0', 'fc8fab1', '898864c', '9f954ae', '5784d1e',
  '10bb63c', '941f69a', '7b1e587', 'ee47e8e', '4ba3fb0', 'd2ba323',
  'b081a5f', 'e936515', '9c1cc64', '829dbe2', '8d14800', '0521dc9',
  '64c3951', '0974e00', 'a279fcb', 'f7ab0c1', '7339975', '94c157f',
  '79f1701', '9e757fc', '809a70b', 'b427109', 'c93b520', 'f37a1cf',
  '5478934', '43eceee', '03019c2', '66cdf34', 'ecc6428', '2ee270e',
  '9b9fc8e', 'b8c2efb', 'f546906', 'eb4a543', 'e417504', '0bc4177',
  '5ad3152', 'fc8200a', '5eab5f0', 'b04d673', '28855eb', '174be04',
  '158c3bd', '3535f23', 'de7e543', '483b43c', '431d52a', 'ceafff7',
  '369e7a3', '98aa6ea', '80dec06', '5482c28', 'edf5b86', 'eca6d5e',
  'c3a0fc2', '864d570', 'afed8e4', 'a5dab0a', 'b8c3e33', 'f836759');

vcf::xen_hypervisor::check_version_and_report(app_info:app_info, fixes:fixes, severity:SECURITY_NOTE);
