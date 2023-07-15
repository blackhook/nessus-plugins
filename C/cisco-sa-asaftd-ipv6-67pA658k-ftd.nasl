#TRUSTED 22d1e73608f2548436256f54c61e0f56fd38c9cde94e55adbd8f8815b4a440d792c660002f9d28d07d072d948136b975da4939a1b03cf2282ad4dded56bca610cda87621513a5df09389489f0c36072b47e82f050bbb9758a96888e3782813e9fda451e81bab29fe5aa7e0b3d91460655d2a3c381e577db0dc30e23d6c67ed775c2111c4ca14026c7379e192e20219cc15c0949a4d82f2e99fbb51290fa745a9a3dc0a92c1f205ec39699200d4a74852f418bf36cf1ab5e8e5358ac18aed597c59bb0aa499c8dd47482c032c0bef8a767993bfe81a235a321741a2facbb4d629ecaba10ce9f9ecec681db98d5b95d44fef8a184a0ec7585cf7cde7c5fa3d490c29cae062fcf6e2057f3cfb1c80a908753a1e8b3bcb66189d3d5d24101d36e9c2160e162f5b62dd85204e72a8cc63d06837a4cfb623d1e2538d5998ab15a5a77d8c8f342643d8cc148c1afb3dd6f155492706bbb23067c5a48988225138a10383f96c7eed7180d1bb66859dd99b8dc24aa3f800b903947f8b867211c5294a745289b2cfb5d407657eb03b1645afcc0ce740de84a6a501b65ec0a199d345ab8b1bcedacefaa9ac1656d384282fa0d89e73879124f016dfb0fb316d4717c1f10465aade06bf30e93f68118ec255990cb6b373472b0530f0edfdba1440cbcace31671a056cdf547ef32eb5693d501ca334393e2ba6f160e8eb1d0a72c129d6994441
#TRUST-RSA-SHA256 8888394489152b1de8e9c0656f978c464788a06917b87fe316b308c9daeb65ac4bb1f9ef079fd531e034c59eb617f2ce4c098472aabc13c5434ce6f068e76d335746221d23d9820da23b7e59082cbcd3c936060cb27775a888534844220a9ff96272853cb1fa680d5f293130cedcc7725d55c3ff31e1ba8da1bb388315e29b0757f72ab22426d31a10cf130a92bb58bbbd43b4deb4e0fa392a3895113e52767010b843eac8cb30da902061c6418a8ea7bfb2ce615876249eda895c7858dc276d633556b7170387e8485f0f96965a1ca905f671079a9c9868065e6a3935958b9579f63f86b49f49955b7af49ea5df3235cf186f16faf7ed4f0bb15e546a125dcfc33e1e36b4f791202f71fd83f05c50d9a7d75c490357ca2737bc2768dbd3d14842c08d6e7821045c6204aabff7d2f55c3531fad3ca512d0f2556758b1375b138a445a9c4f73ea20eb259178d517ded2641b59dd26ee096076a64b970dcf64461a38497aaef7e06fba3ae8ca7d759f3bb0baa706ded8e3d1e6c72537b2a9e2c0f9bf789f79993583abd0c2fd1112aeaabf884894f6414f5ae6f4f0ed581d7c9a81f2914caaf208717b2ff5704c3ed833dcacc8e827185fd94f7b43ea6bf49cef6d6c1c158a1c24271fb6e9e15e51939e7e903625df8e48d292ff529fb2445bfe6b1b2ccf53d5e9f79c073a139a26cb505afe0755755698753a8c530bb0369b50f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137662);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3191");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr07419");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-ipv6-67pA658k");
  script_xref(name:"IAVA", value:"2020-A-0205-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0042");

  script_name(english:"Cisco Firepower Threat Defense (FTD) DNS Denial of Service (cisco-sa-asaftd-ipv6-67pA658k)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense (FTD) Software is affected by a denial of 
  service (DoS) vulnerability in IPV6 DNS packet processing component due to insufficient validation of user-supplied 
  input. An unauthenticated, remote attacker can exploit this issue, by sending specially crafted IPV6 DNS packets to 
  an affected device, to cause a denial of service condition. 

  Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ipv6-67pA658k
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f09a07e9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr07419");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr07419.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3191");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '6.2.3.16'},
  {'min_ver' : '6.3.0', 'fix_ver' : '6.3.0.6'},
  {'min_ver' : '6.4.0', 'fix_ver' : '6.4.0.6'}
];

expert = get_kb_item('Host/Cisco/FTD_CLI/1/expert');
is_ftd_cli = get_kb_item_or_exit('Host/Cisco/Firepower/is_ftd_cli');

# Requires hotfix check + workaround. If neither are possible, require paranoia
if (!expert || !is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);
}

if (!is_ftd_cli)
{
  workarounds = make_list();
  extra = 'Note that Nessus was unable to check for workarounds or hotfixes';
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['dns_non_local_routes']);
  workaround_params = make_list();
  cmds = make_list('show ipv6 route summary');

  if (expert)
  {
    hotfixes['6.2.3'] = {'hotfix' : 'Hotfix_DT-6.2.3.16-3', 'ver_compare' : FALSE};
    hotfixes['6.3.0'] = {'hotfix' : 'Hotfix_DT-6.2.3.16-3', 'ver_compare' : FALSE};
  }
  else
  {
    extra = 'Note that Nessus was unable to check for hotfixes';
  }
}

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr07419',
  'fix'      , 'See vendor advisory',
  'extra'    , extra
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  workarounds:workarounds,
  workaround_params:workaround_params,
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  firepower_hotfixes:hotfixes
);
