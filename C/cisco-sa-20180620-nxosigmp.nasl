#TRUSTED 3a072afedcbca14201bbd3cb274ab26f9600eb034a927567f7dfc75b8e0e26d1fe8862d864963d79091964ffac09d27d2986feeaaa1e4c4109f341fe1b2aba7facffb1ce4f5ae9be38163e992407284dc14dbf93e3e631d24b30e00666c40e7bc8b1c7256b8ddc576277ad9d543575442765c4c0668d8160afa495dce868d83aab28bfb91e0b485ab9d4155fcf3cf99635391ffcaf88ceb2a49a42d513b4478c4f65eee5d61bfc02109d8ab564b2ae5833e9134f6a9ad0f6cf2b1ff36fc731dfc3674d9f4813aaeb4a58ce3990d17eb2937b822a4ddb650a4a75249a14c1d66dd767ed1cb9d01474e2ce63dfee0a4cdebf560077658ca667242cf56bb1838e34a986449cf28d1acd00cb799e1c9d87f077b53435565adfd6170774bbd46ad91a65aebb08030644bb3e364949d9b491c721407ab7dc3ababaa960e691dd365c4e664f1f379c69a8898afde28aafe11b93ac933941ae8a527a9574ae1a3de7e8ed704e06a4b0c186625996c5d052e659936c539ea8deaaf30926f60eea8fbbaf5ba26c3ed467a7b9d8f4b3448c64c48da912ca71d7adad8fe6d41e0f543830c62cf12ce5b6359c773f483aa70b8286a0dd1ce5f6bc9ff2c5fdfab201a769da691a7ffc8dff6780f799e5f0cc9fc09ea3f5d79980c9f10d1286c825d75feb9ff7f700d925eb6b3934945d18c2cf22d49233c1d45ac8f6979e2e71f8cf566f3cc354
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138352);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/10");

  script_cve_id("CVE-2018-0292");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv79620");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg71263");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-nxosigmp");

  script_name(english:"Cisco NX-OS Software Internet Group Management Protocol Snooping RCE and DoS (cisco-sa-20180620-nxosigmp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a due to a
buffer overflow condition in the IGMP Snooping subsystem. An attacker could exploit this
vulnerability by sending crafted IGMP packets to an affected system. An exploit could 
allow the attacker to execute arbitrary code and gain full control of the affected system
or cause the affected system to reload, resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-nxosigmp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c23231bb");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuv79620");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg71263");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCuv79620, CSCvg71263");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0292");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

cbi = '';
version_list=make_list('');

if ('Nexus' >!< product_info.device)   
    audit(AUDIT_HOST_NOT, 'affected');

if (product_info.model =~ "^30[0-9][0-9]")
  {
    cbi = 'CSCuv79620';
    version_list = [
    {'min_ver' : '0.0', 'fix_ver' : '7.0(3)I4(1)'},
    {'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I7(1)'}
    ];
  }
else if (product_info.model =~ "^(20|55|56|60)[0-9][0-9]")
  {
    cbi = 'CSCuv79620';
    version_list = [
    {'min_ver' : '6.0', 'fix_ver' :'7.3(3)N1(1)'}
    ];
  }
else if (product_info.model =~ "^90[0-9][0-9]")
  {
    if (empty_or_null(get_kb_item("Host/aci/system/chassis/summary")))
    {
      cbi = 'CSCuv79620';
      version_list = [
      {'min_ver' : '0.0', 'fix_ver' : '7.0(3)I4(1)'},
      {'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I7(1)'}
      ];
    }
    else
    {
      cbi = 'CSCvg71263';
      version_list = [
      {'min_ver' : '0.0', 'fix_ver' : '13.1(1i)'}
      ];
    }
  }
else if (product_info.model =~ "^35[0-9][0-9]")
  {
    cbi = 'CSCuv79620';
    version_list = [
    {'min_ver' : '6.0(2)', 'fix_ver' : '7.0(3)I7(2)'}
    ];
  }
else if (product_info.model =~ "^7[70][0-9][0-9]")
  {
    cbi = 'CSCuv79620';
    version_list = [
    {'min_ver' : '6.2', 'fix_ver' : '8.1(2)'}
    ];
  }
else if (product_info.model =~ "^95[0-9][0-9]")
  {
    cbi = 'CSCvc88167';
    version_list = [
    {'min_ver' : '7.0', 'fix_ver' : '7.0(3)F3(3)'}
    ];
  }
else audit(AUDIT_HOST_NOT, 'affected');

workarounds = make_list(CISCO_WORKAROUNDS['show_running-config']);
workaround_params = {'pat' : 'ip igmp snooping'};

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
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
