#TRUSTED 3c0dab94b7f4d35d1074c465c80598eaf63efeea27ee7d9290b44ec765fd0b42d2d1579f19dd886d20d408f3b2a3de94457ed568b88a14d2b3cc3d6259d92b14a81516cefa61a9349909bc5747217523c17369747a7a18958e34425afb066eb2cb998be0b5b965d0cc3b1c33763ba49a0b8877bbb303c7d65bc6339335a14062f89bd8063eb5509b26119e664c3b5b286f1b991bdb1efaed1af76b73f689776ef5752bab06635b849bbca657dd7bd66c058854394cf2790249c09e60c53dedefd35bfcc40a7c64a3c29d8559e31640d0d42e370e65e6596044301ce07cdcdb2bbafb833e4a8520e88b9c5e10f8e305a69a8a7a990ee237d7e05d1545c0d7626a8960ad14760edd35c33b986d546c7da11c2e25957067a0e50b7eefb9c370fc79ab8ef8f86599debaadfcac6d6fe4f71475be2a9708050e4c6bf41d4bba2f2798569297b4dc9f4032033a69d094908189020581ab1a72082153dfe7e9ece77480c6d99265f8f98722d915be6a578d6108400d915a7a20c90bd7c7b87a5a2d70be7ead5ea4cd13e219a0d061f8f58a64613a284cc62cc500907d435d532e5f9104eede62773c786f3fe862a63be38684a3c523da4e18749fdba1ba4e185e4729963ea07acd11b13517a889de9a8ca6a792983cde2f1844227a93fd9ec913c810d909cb5a7789f364e4b243b963ffc57f8c0e6af8c0a96f765b921ee07f2ed0727d
#TRUST-RSA-SHA256 7af78ff94bcb6819171220a463587d77619babb8c6e0d68fffa9eb47caa7376ff27be6ea85ffdd90685d7d68eda4a6a39a9595ec69acf4290d4de9e0c349756ea9239e2e33f2933e4b3189ecde2a87bf639680dcf20cd0fd5309035b34f2d6ea5f1ea10368b303d824968a5bb692608e7a2bb4e6e58c9e80c6968d0fffe4c3ec3700e553ab633740b477d2b6fc14ba58aa76d743313db92c2bd82833c4b9ad2bde7bf2e35dd891251004b5851b6c2b1a526648dc13983d46281125f2c1d02234c0177defe9c70c5e534ec981eca12ee63b81b771c887199b470635c82979ee8e6c08639c7f137eb05be6659320d63d797ccdd4a607a68dcc67d1d9a7185a6a8f25827bef3d26adff5d5230bf39b1ab75c8fb7fcd6ffb8c628a7aa676d146b8740a42d14e17bfadbe46eb3a37224c48be704d042cbc335aa4f935963c2c1cdd67634d4b6b0b4c41f97e3339307df19e62fa1de4b8ddfad40d6cb25cbaf8912a9a844b8441559a92ceb4862fa934ba493b02ca97e4b15da33552e482276ccd8c9403c0498532e44e23d3b0b899bc6ffc4b0fa4610a75eecc02cab4d11bd305ace59eff4ab68658a4069bf376f262e61f5ccbd081d3364db7783f689f3d3861721303ec7b425b15ef5105a7e2955720eea628723a6b5028826819aa22e1a623430d87b619ef6c12ac9ba00227c32f34b9251b38acedffe77c01092493d0af393cc4
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132680);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-0155");
  script_bugtraq_id(103565);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc40729");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-bfd");
  script_xref(name:"IAVA", value:"2018-A-0098-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");

  script_name(english:"Cisco IOS Software Bidirectional Forwarding Detection DoS (cisco-sa-20180328-bfd)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by a denial of service (DoS) vulnerability in the
Bidirectional Forwarding Detection (BFD) offload implementation due to insufficient error handling when the BFD header
in a BFD packet is incomplete. An unauthenticated, remote attacker could exploit this, by sending a crafted BFD message
to or across an affected switch, in order to crash the iosd process and trigger a system reload.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-bfd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c66d9346");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc40729");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvc40729.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0155");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS');

if ('catalyst' >!< tolower(product_info.model) || product_info.model !~ "4[59]\d\d(^\d|$)")
  audit(AUDIT_HOST_NOT, "affected");

version_list = make_list(
  '15.1(1)SG',
  '15.1(2)SG',
  '15.1(1)SG1',
  '15.1(1)SG2',
  '15.1(2)SG1',
  '15.1(2)SG2',
  '15.1(2)SG3',
  '15.1(2)SG4',
  '15.1(2)SG5',
  '15.1(2)SG6',
  '15.1(2)SG7',
  '15.1(2)SG8',
  '15.2(1)E',
  '15.2(2)E',
  '15.2(1)E1',
  '15.2(3)E',
  '15.2(1)E3',
  '15.2(2)E1',
  '15.2(2b)E',
  '15.2(4)E',
  '15.2(3)E1',
  '15.2(2)E2',
  '15.2(2)E3',
  '15.2(3)E2',
  '15.2(3)E3',
  '15.2(4)E1',
  '15.2(2)E4',
  '15.2(2)E5',
  '15.2(4)E2',
  '15.2(3)E4',
  '15.2(4)E3',
  '15.2(2)E6',
  '15.2(2)E5a',
  '15.2(3)E5',
  '15.2(2)E5b',
  '15.2(4)E4',
  '15.2(2)E7',
  '15.2(4)E5',
  '15.2(2)E7b',
  '15.2(4)E5a',
  '15.2(4s)E2'
);

# Script is paranoid, so workarounds should be omitted
workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvc40729',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
