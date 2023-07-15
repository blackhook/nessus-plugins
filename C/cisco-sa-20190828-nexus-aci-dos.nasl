#TRUSTED 67771ca480838fa3c11d33338925b45e581293f6505c28c7c56adb63e5365405ed01f20967b3450c6f95c68060e4a1ad40c462718a79ed9daa5b196ac1244293c55e3dbbeac14e2696378b4aa912d8e6093f4b70242021c0cd7a62ae99bb3b6852e37b08174b58270954682ac6fe38cfcae24856bd5dc2c303b457d9aa1f2251bbc39cdfaf075b3abb711b89aea6c8c5d8f3c55b4c0eb3ecc7e7399a2431eb9aa9d097dd22f0399428b632b0f37617d9bb6baa4810b96d8a2bae13877367bea9dfddea8eb23bd662df2c12f7e8153c9bb6d3813f2fb12735302c7d360b9161455f0a45a7287481a43c0ad9b0c6ad06b17a352e5e42f1308a6d8fe496161788a4c59ac456bef27ec91ece823b4e1f75f8e5512e1b740a254c6b7b1a0e163df47959a6e09cc953a08b8f75aff62cfd47ef88f0f4a8039fc01f96e1137fd9dbf73747209e5c1166410a7feca8c5a1fe0b63c138c2fb8f74802eff2ef00efafcf57f925d8616bb0c603feac535f21fd9785ed45a6e8640c2c53569f538031f3b859274cd9689907e5b505fbf5506a649e5fd8e827616e769faba6afd90877704372161e497c10d4cfd375f02a0284280b729d5daaa6a6c48ed0a8157d66ea10660ce080889a46f0da403d719e35270cf014ba9527251de5699384b9771a8b139086a318417358fc1c2187d2ec091928cd12e41b6b82f974ffc842fb91af05c4f0d8d
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132855);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2019-1977");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi11291");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190828-nexus-aci-dos");
  script_xref(name:"IAVA", value:"2019-A-0317");

  script_name(english:"Cisco Nexus 9000 Series Fabric Switches ACI Mode Border Leaf Endpoint Learning (cisco-sa-20190828-nexus-aci-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS System Software in Application Centric Infrastructure (ACI) mode is
affected by a vulnerability within the Endpoint Learning feature of Cisco 9000 Series Switches due to improper endpoint
learning when packets are received on a specific port from outside the ACI fabric and destined to an endpoint located on
a border leaf when 'Disable Remote Endpoint Learning' has been enabled. An unauthenticated, remote attacker can exploit
this to create a Remote (XR) entry for the impacted endpoint that will become stale if the endpoint migrates to a
different port or leaf switch. This results in traffic not reaching the impacted endpoint until the Remote entry can be
relearned by another mechanism, causing a denial of service (DoS) condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190828-nexus-aci-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9a5ce967");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi11291");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi11291");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1977");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ '^90[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '12.0(1m)',
  '12.0(2g)',
  '12.0(1n)',
  '12.0(1o)',
  '12.0(1p)',
  '12.0(1q)',
  '12.0(2h)',
  '12.0(2l)',
  '12.0(2m)',
  '12.0(2n)',
  '12.0(2o)',
  '12.0(2f)',
  '12.0(1r)',
  '12.1(1h)',
  '12.1(2e)',
  '12.1(3g)',
  '12.1(4a)',
  '12.1(1i)',
  '12.1(2g)',
  '12.1(2k)',
  '12.1(3h)',
  '12.1(3j)',
  '12.2(1n)',
  '12.2(2e)',
  '12.2(3j)',
  '12.2(4f)',
  '12.2(3p)',
  '12.2(3r)',
  '12.2(3s)',
  '12.2(3t)',
  '12.2(2f)',
  '12.2(2g)',
  '12.2(2i)',
  '12.2(2j)',
  '12.2(2k)',
  '12.2(2q)',
  '12.2(1o)',
  '12.2(1k)',
  '12.3(1e)',
  '12.3(1f)',
  '12.3(1i)',
  '12.3(1l)',
  '12.3(1o)',
  '12.3(1p)',
  '13.0(1k)',
  '13.0(2h)',
  '13.0(2k)',
  '13.0(2n)',
  '13.0(1i)',
  '13.0(2m)',
  '13.1(1i)',
  '13.1(2m)',
  '13.1(2o)',
  '13.1(2p)',
  '13.1(2q)',
  '13.1(2s)',
  '13.1(2t)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info.version,
  'bug_id'   , 'CSCvi11291',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  switch_only:TRUE
);

