#TRUSTED 0552e32b8b28001833386bb1fcba5f8646b476e0cc3f9f02923abe24079f889952681bb00daf564b1213b80c6aba890e319b0e21ef377190bdca3720deca767294369057e378db60245c86f8c445f33a8fb8bd54d314160aa1eb8b352073b4e9f96b54cc6af11543e23b3d412a2716a54e839dddd7e11a5ce0594ce40c6910ae569b33bd079e803e992cf2f90d4108073ec7cbc42c4ac8e9111a85ec447156fc89208902cff3dd0f89967c9e638c6ef44df2310b1f929ec7b0953ceca5e294b6193c33fdcb3772a1dc6ab9df9ebcb643a18ffaabb28898660d7093d40c508a143b4068fe93dd15b55296dc3712132b2d6b67e14201b95350b6f41ad595859eb265fb75d66a8b428105c6bef0a140264c3d4afc714f626240a0dbfdd5dd964cdb3c6f26a2b8aee290959e0b63857a5c8d4a0fea524e42c16c663bfda6c9805d8b6d1576100e2ec99efb5a8d92b6d7f1bc8fdf0000504f167ae609c1d5853a51c48d58e6f9d2bbc7f71468c8db60d834cba314adbf58e2e1d8b087d52c345166f2d0822e8def66d30f463e8892038336dee2140aa728b9f0d3b7862310471db093cf87ed614c2ab34acccce9f420431ae711b06cb6059f3f5da089af83b78bdc673a07a49efd39a065633c379572d57a63b6988e0405c56507d436f1d69557581697d378f365f65cdc035e15092107eb8ff47abead4eb7492865d006baa0cd6239
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138350);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/20");

  script_cve_id("CVE-2018-0331");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc89242");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve40943");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve40953");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve40965");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve40970");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve40978");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve40992");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41000");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41007");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-nxos-cdp");

  script_name(english:"Cisco FXOS, NX-OS, and UCS Manager Software Cisco Discovery Protocol DoS (cisco-sa-20180620-nxos-cdp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a denial of 
service (DoS) vulnerability exists in Cisco Discovery Protocol due to failure to properly 
validate certain fields within a Cisco Discovery Protocol message. An unauthenticated, 
adjacent attacker can exploit this issue, via submiting a Cisco Discovery Protocol message,
to cause the system to stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-nxos-cdp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31020d41");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc89242");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve40943");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve40953");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve40965");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve40970");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve40978");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve40992");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41000");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41007");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvc89242, CSCve40943, CSCve40953, CSCve40965,
CSCve40970, CSCve40978, CSCve40992, CSCve41000, CSCve41007");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0331");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

var cbi = '';
var version_list=make_list('');

if ('MDS' >< product_info.device && product_info.model =~ "^90[0-9][0-9]")
  {
    cbi = 'CSCve40970';
    version_list = [
      {'min_ver' : '5.2', 'fix_ver' : '6.2(21)'},
      {'min_ver' : '7.2', 'fix_ver' : '7.2(2)D1(3)'},
      {'min_ver' : '7.3', 'fix_ver' : '7.3(2)D1(1)'},
      {'min_ver' : '8.1', 'fix_ver' : '8.1(1a)'}
    ];
  }
else if ('UCS' >< product_info.device && product_info.model =~ "^6[123][0-9][0-9]")
  {
    cbi = 'CSCvc89242';
    version_list = [
      {'min_ver' : '0.0', 'fix_ver' : '2.2(8g)'},
      {'min_ver' : '2.5', 'fix_ver' : '3.1(2f)'}
    ];
  }
else if ('Nexus' >< product_info.device) 
  {
  if (product_info.model =~ "^1(1[0-9][0-9]|0[0-9][0-9][vV])")
    {
      cbi = 'CSCve40992';
      version_list = [
        {'min_ver' : '0.0', 'fix_ver' : '5.2(1)SV3(3.15)'}
      ];
    }
  else if (product_info.model =~ "^30[0-9][0-9]")
    {
      cbi = 'CSCve40965';
      version_list = [
        {'min_ver' : '0.0', 'fix_ver' : '7.0(3)I4(7)'},
        {'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I5(3b)'},
        {'min_ver' : '7.0(3)I6', 'fix_ver' : '7.0(3)I6(2)'},
        {'min_ver' : '7.0(3)I7', 'fix_ver' : '7.0(3)I7(1)'}
      ];
    }
  else if (product_info.model =~ "^35[0-9][0-9]")
    {
      cbi = 'CSCve40953';
      version_list = [
        {'min_ver' : '6.0', 'fix_ver' : '6.0(2)A8(5)'},
        {'min_ver' : '7.0.3', 'fix_ver' : '7.0(3)I7(2)'}
      ];
    }
  else if (product_info.model =~ "^(20|55|56|60)[0-9][0-9]")
    {
      cbi = 'CSCve40978';
      version_list = [
        {'min_ver' : '6.0', 'fix_ver' :'7.1(5)N1(1)'},
        {'min_ver' : '7.2', 'fix_ver' :'7.3(3)N1(1)'}
      ];
    }
  else if (product_info.model =~ "^7[70][0-9][0-9]")
    {
      cbi = 'CSCve40970';
      version_list = [
        {'min_ver' : '6.2', 'fix_ver' : '6.2(20)'},
        {'min_ver' : '7.2', 'fix_ver' : '7.2(2)D1(3)'},
        {'min_ver' : '7.3', 'fix_ver' : '7.3(2)D1(1)'},
        {'min_ver' : '8.0', 'fix_ver' : '8.1(2)'},
        {'min_ver' : '8.2', 'fix_ver' : '8.2(1)'}
      ];
    }
  else if (product_info.model =~ "^90[0-9][0-9]")
    {
      cbi = 'CSCve40943';
      version_list = [
        {'min_ver' : '0.0', 'fix_ver' : '7.0(3)I4(7)'},
        {'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I6(2)'},
        {'min_ver' : '7.0(3)I7', 'fix_ver' : '7.0(3)I7(1)'}
      ];
    }
  else if (product_info.model =~ "^95[0-9][0-9]")
    {
      cbi = 'CSCve41000';
      version_list = [
        {'min_ver' : '7.0', 'fix_ver' : '7.0(3)F3(1)'}
      ];
    }
  else audit(AUDIT_HOST_NOT, 'affected');
  }
else audit(AUDIT_HOST_NOT, 'affected');

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['global_cdp_info'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , cbi
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
