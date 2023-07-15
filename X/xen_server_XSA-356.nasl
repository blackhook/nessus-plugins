##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144743);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-29567");
  script_xref(name:"IAVB", value:"2020-B-0077-S");

  script_name(english:"Xen IRQ Infinite Loop DoS (XSA-356)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor installed on the remote host is affected by a denial
of service vulnerability due to an issue when handling IRQ vectors. When moving IRQs between CPUs to distribute the load
of IRQ handling, IRQ vectors are dynamically allocated and de-allocated on the relevant CPUs. De-allocation has to
happen when certain constraints are met. If these conditions are not met when first checked, the checking CPU may send
an interrupt to itself, in the expectation that this IRQ will be delivered only after the condition preventing the
cleanup has cleared. For two specific IRQ vectors, this expectation was violated, resulting in a continuous stream of
self-interrupts, which renders the CPU effectively unusable. A domain with a passed through PCI device can cause lockup
of a physical CPU, resulting in a Denial of Service (DoS) to the entire host. Only x86 systems are vulnerable. Arm
systems are not vulnerable. Only guests with physical PCI devices passed through to them can exploit the vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-356.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch or workaround according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-29567");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/05");

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

fixes['4.14']['fixed_ver']           = '4.14.1';
fixes['4.14']['fixed_ver_display']   = '4.14.1-pre (changeset d785e07)';
fixes['4.14']['affected_ver_regex']  = "^4\.14\.";
fixes['4.14']['affected_changesets'] = make_list('d8f08a4', '5174e42',
  'bfc99c3', '13268c5', 'de822c4', '57bbcd0', '7214cc7', '49ed711',
  'dc871dd', 'b1c5e40', '61d3863', '9e53440', '335ef5b', '6fa3e05',
  'f4405b6', '228e562', '0a79a1b', '5073c6b', '5259358', '3d0e1a1',
  '117521e', '91992c7', '4e298fa', '3beffb3', 'da67712', '9c898a8',
  'f130d5f', '1d1d1f5', '72bd989', '8e6c236', '1cfb9b1', '7c6ee4e',
  'd11d977', '1ad1773', '0057b1f', 'd101b41', 'd95f450', '73a0927',
  'a38060e', '78a53f0', '89ae1b1', '7398a44', '59b8366', '1f9f1cb',
  'f728b2d', '71a12a9', '0c96e42', '29b48aa', 'd131310', '7d2b21f',
  'f61c5d0', 'fc8fab1', '898864c', '9f954ae', '5784d1e', '10bb63c',
  '941f69a', '7b1e587', 'ee47e8e', '4ba3fb0', 'd2ba323', 'b081a5f',
  'e936515', '9c1cc64', '829dbe2', '8d14800', '0521dc9', '64c3951',
  '0974e00', 'a279fcb', 'f7ab0c1', '7339975', '94c157f', '79f1701',
  '9e757fc', '809a70b', 'b427109', 'c93b520', 'f37a1cf', '5478934',
  '43eceee', '03019c2', '66cdf34', 'ecc6428', '2ee270e', '9b9fc8e',
  'b8c2efb', 'f546906', 'eb4a543', 'e417504', '0bc4177', '5ad3152',
  'fc8200a', '5eab5f0', 'b04d673', '28855eb', '174be04', '158c3bd',
  '3535f23', 'de7e543', '483b43c', '431d52a', 'ceafff7', '369e7a3',
  '98aa6ea', '80dec06', '5482c28', 'edf5b86', 'eca6d5e', 'c3a0fc2',
  '864d570', 'afed8e4', 'a5dab0a', 'b8c3e33', 'f836759');

vcf::xen_hypervisor::check_version_and_report(app_info:app_info, fixes:fixes, severity:SECURITY_WARNING);
