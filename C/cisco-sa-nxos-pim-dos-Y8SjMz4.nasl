#TRUSTED 9b10c48cee19704da6b9ccd1f0c9e03d2f6870a0d25e17f125156f348cef9f5fd89d52744a0aa189c0444e3d345bfd0b16fb4aa4992b4046662e2c2ae7b71b4d35e3c34dc277a9333a1383a27163df14157d4831c217cb63478b5baedce7f09e6f2ac7d76b9294f5312e53e919805ee801aed797728b4787da5d63a7fd534d7930c72a07b1d22ea7a388dc601bd08f022103fc4b6bae53433bbd9165cc1f676962d4d4ba6d379536d8460a66b19cd271541b68d32eb04c9c96ecb4be40c8a9925d96932016bcae0cada8f6cff44d29103d04d2f753b900197f9a5606ce653267977e2740a7cca3dcd12589e5711575d6efc6ba8b66a1c31a72ee456723d01b4bd02366b210d5262c596345709cf9d45242db42a774165269065f5b37be80e990eee1a04fb2f20b6dab8cd6c6d8258f9867abcfb41684cae9acc86b59a3b3e1faad8ae32ce638e04c52511680243d75196919eb1a4249f30a0e254af2ec68c22614f5ff85fb022925a6a83aff2d4a72d11caee6d365138853df732c2975795741ea2077b06389b69b87407a801584be36b8fd817fd43751a774d8862c07a104831a095bb18cd4b49ceef3762b03e89a0e42fee7a7aaeaceb921a3416dccc5e1b9ed3c146b12a6f556290ab74000c9e44550729c572bee17c950fd5fa285eb1e974b8aee09c6db556eb003b3bc986fc40415e1dfd6a19c7aa7f21bf9d407eff43a
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146804);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/12");

  script_cve_id("CVE-2021-1367");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98438");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-pim-dos-Y8SjMz4");
  script_xref(name:"IAVA", value:"2021-A-0113");

  script_name(english:"Cisco NX-OS Software Protocol Independent Multicast Denial of Service Vulnerability (cisco-sa-nxos-pim-dos-Y8SjMz4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-nxos-pim-dos-Y8SjMz4)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-pim-dos-Y8SjMz4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a858b98");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98438");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv98438");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1367");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if (('Nexus' >!< product_info.device || product_info.model !~ "^95[0-9]{2}"))
audit(AUDIT_HOST_NOT, 'affected');

version_list = make_list(
  '7.0(3)F2(1)',
  '7.0(3)F2(2)',
  '7.0(3)F3(1)',
  '7.0(3)F3(3)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(4)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(5)',
  '9.2(1)',
  '9.2(2)',
  '9.2(3)',
  '9.2(3y)',
  '9.2(4)',
  '9.3(1)',
  '9.3(2)',
  '9.3(3)',
  '9.3(1z)',
  '9.3(4)',
  '9.3(5)',
  '9.3(5w)'
);

workarounds = make_list(CISCO_WORKAROUNDS['show_running-config']);
workaround_params = {'pat' : "\s*feature\s+pim($|\r\n)"};

reporting = make_array(
  'port'     , 0,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv98438',
  'severity' , SECURITY_NOTE,
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
