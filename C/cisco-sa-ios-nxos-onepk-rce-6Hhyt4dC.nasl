#TRUSTED 0ac81eec669f88a8ecf197444af9e891fa3eb9f5ffc1dc36666ed63926e0191515a070e28cba4198637d159634aec18aba0f0345f0e8c304c631f13d41c17b6e12391b7695f55fbec654d38c6859fd97a1249b02e3610bf2d6575eea18e2700394abde52afebc783457df9ca8e8fadcfb8837a8bfcad494bd0b9de9d04ad228e473849cef873238457eb99884cbcd5fc4e2cb5ccfac8b88286da5a1c7fab26fbebe4d4087f4fadc5f3deb3b650633e0ca286c695bded6ed6bef953686e36db7904dc73cac55efbfd42723bf24eebe4ba2c7c1e2dc294c73521fa3cca4341ee535b70b751d1d2fdf600255ab14534d7886a04fddb716db94594a887a2ac0d18921756e66f30fae073ccfe43dd2e4ebdf0d0b7eccc016682aa057dc85af640e446b004b376f22a1b5562c00854183ce6ef6f6e39ffeb6e0bf454c4c9f2feba0d043fb93d6cc5717177f0eeb56e15df283f6383e142f39f009d0c5a3887362018190759248427692b0903ef6ae4dfff46397f1ebfdede97f255338abc48edd60a6de8e17ae2ccabf27e47fde191719b7d7fbf1870f4bedbf9ae89a5cbc0e4750c4ca5a015ef06a5f4d988bd3c4ae1c91b3e3c74adfe5e6f92f6f6fd27a2d8d7a7712ccacc4249f500d1ead546d7eb8f6bc2e6e1a594bec0bd6e8c00d84c53ad6ba0fb82884e79b4c6cd9452654b51b04992a60bbe8eab8b8eb5c8bfd8abf67599da
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137903);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id("CVE-2020-3217");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh10810");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr80243");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs42159");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs42176");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs81070");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-nxos-onepk-rce-6Hhyt4dC");
  script_xref(name:"IAVA", value:"2020-A-0260");

  script_name(english:"Cisco NX-OS Software One Platform Kit Remote Code Execution Vulnerability (cisco-sa-ios-nxos-onepk-rce-6Hhyt4dC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-ios-nxos-onepk-rce-6Hhyt4dC)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NXOS is affected by a remote code execution vulnerability.
Therefore there exists in Cisco One Platform Kit due to a vulnerability in the Topology Discovery Service.
An unauthenticated, adjacent attacker can exploit this to bypass authentication and execute arbitrary 
commands with root privileges. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-nxos-onepk-rce-6Hhyt4dC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38e0a857");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh10810");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr80243");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs42159");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs42176");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs81070");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvh10810, CSCvr80243, CSCvs42159, CSCvs42176,
CSCvs81070");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3217");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:"Cisco NX-OS Software");

vuln_ranges=make_list();

if ('Nexus' >< product_info.device) 
    {
    if (product_info.model =~ "^[39]0[0-9][0-9]")
        {
        vuln_ranges = [
          {'min_ver' : '0', 'fix_ver' : '7.0(3)I7(8)'},
          {'min_ver' : '8.0', 'fix_ver' : '9.2(1)'}
          ];
        }
    else if (product_info.model =~ "^(60|55|56)[0-9][0-9]")
        {
        vuln_ranges = [
          {'min_ver' : '0', 'fix_ver' : '7.3(7)N1(1)'}
          ];
        }
    else if (product_info.model =~ "^70[0-9][0-9]")
        {
        vuln_ranges = [
          {'min_ver' : '0', 'fix_ver' : '8.4(2)'}
          ];
        }
    else audit(AUDIT_HOST_NOT, 'affected');
    }
else audit(AUDIT_HOST_NOT, 'affected');

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['onep_status'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvh10810, CSCvr80243, CSCvs42159, CSCvs42176, CSCvs81070'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  workarounds:workarounds,
  workaround_params:workaround_params
);
