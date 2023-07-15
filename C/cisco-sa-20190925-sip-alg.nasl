#TRUSTED 6111aecd2a98cd547fa56b71ce998545a883ce10858b933146cbceb8e2ce22d7f8f36e0bfc06c82ae52229873bf5652361b72f349e0428d38be805e421f4d58fbb68d75851e7a40fc831fa03c21e069d2b03bec359746f548808613d79d335c051c5a1df377bfbd927553236cc2cd484bf78fc27f1c204b31a9112d3610e06041b84db4df4b8b3b4f7c4093c736cb6a4ef2fcc77a868b5094b49ecf09b6064eb7c1b193c102f12719b97725f3eefb034bbedbfe883ace45def9306553e37a34e4aebbfe097812856f8ce444f7ef4eceb7f6bd169889ab91a77710d7ece7ae65f3cdec369d365330c7f46c0cc2098f6317f7f4946469648f2cab5e379bdd28832e059033629fe034d2cadfccd695be41d5611480a1f07b29268aa6e6a215f15ef7c72483a91fec107f7f908bfee34a5495cfabd05b63e758409461ca0e1b4f708ea1020f8409629687fa54fa2e3cf700429580d57f671a2bae2e465cefdc84fc958ed6effd8073394457ee537da29be6dbc7cc5b08010d82de4a8d2c7aed55e066b6181861f2e1f3995efeb7b75efd87a4d78cb49f79390a0b2a1bc9f435a0749fddfef754ecd9050c4ac2be919326e1af4e2ad5021800f1af4462744a13eba728b43b59ac6babf1bf5bf73d5f28d568f2f5f6f7c3384c3965cb921fd53ae82c8a0880fb090945c2361f0d87f9d5a00d65dfcf56660cc6e706a9d93fffb0e72de
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129780);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-12646");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn65912");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-sip-alg");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software NAT Session Initiation Protocol Application Layer Gateway DoS (cisco-sa-20190925-sip-alg)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability
in the Network Address Translation (NAT) Session Initiation Protocl (SIP) Application Layer Gateway (ALG). This allows
an unauthenticated, remote attacker to cause an affected device to reload. The vulnerability is due to improper
processing of transient SIP packets on which NAT is performed on an affected device. An attacker can exploit this
vulnerability by using UDP port 5060 to send crafted SIP packets through an affected device that is performing NAT for
SIP packets. A successful exploit could allow an attacker to cause the device to reload, resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-sip-alg
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82cd252a");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-72547");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn65912");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvn65912");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12646");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
model = product_info.model;

if (model !~ "^ISR11\d{2}([^0-9]|$)" &&
    model !~ "^ISR4(3|2)\d{2}([^0-9]|$)" &&
    model !~ "^CSR10\d{2}([^0-9]|$)" &&
    model !~ "^ENCS"
   )
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '3.9.2S',
  '3.9.1aS',
  '3.9.1S',
  '3.9.0aS',
  '3.9.0S',
  '3.8.2S',
  '3.8.1S',
  '3.8.0S',
  '3.7.8S',
  '3.7.7S',
  '3.7.6S',
  '3.7.5S',
  '3.7.4aS',
  '3.7.4S',
  '3.7.3S',
  '3.7.2tS',
  '3.7.2S',
  '3.7.1aS',
  '3.7.1S',
  '3.7.0bS',
  '3.7.0S',
  '3.2.0JA',
  '3.18.4S',
  '3.18.3S',
  '3.18.2S',
  '3.18.1S',
  '3.18.0aS',
  '3.18.0S',
  '3.17.4S',
  '3.17.3S',
  '3.17.2S',
  '3.17.1aS',
  '3.17.1S',
  '3.17.0S',
  '3.16.8S',
  '3.16.7bS',
  '3.16.7aS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.6S',
  '3.16.5bS',
  '3.16.5aS',
  '3.16.5S',
  '3.16.4gS',
  '3.16.4eS',
  '3.16.4dS',
  '3.16.4cS',
  '3.16.4bS',
  '3.16.4aS',
  '3.16.4S',
  '3.16.3aS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.2aS',
  '3.16.2S',
  '3.16.1aS',
  '3.16.1S',
  '3.16.0cS',
  '3.16.0bS',
  '3.16.0aS',
  '3.16.0S',
  '3.15.4S',
  '3.15.3S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.1S',
  '3.15.0S',
  '3.14.4S',
  '3.14.3S',
  '3.14.2S',
  '3.14.1S',
  '3.14.0S',
  '3.13.9S',
  '3.13.8S',
  '3.13.7aS',
  '3.13.7S',
  '3.13.6bS',
  '3.13.6aS',
  '3.13.6S',
  '3.13.5aS',
  '3.13.5S',
  '3.13.4S',
  '3.13.3S',
  '3.13.2aS',
  '3.13.2S',
  '3.13.1S',
  '3.13.10S',
  '3.13.0aS',
  '3.13.0S',
  '3.12.4S',
  '3.12.3S',
  '3.12.2S',
  '3.12.1S',
  '3.12.0aS',
  '3.12.0S',
  '3.11.4S',
  '3.11.3S',
  '3.11.2S',
  '3.11.1S',
  '3.11.0S',
  '3.10.9S',
  '3.10.8aS',
  '3.10.8S',
  '3.10.7S',
  '3.10.6S',
  '3.10.5S',
  '3.10.4S',
  '3.10.3S',
  '3.10.2tS',
  '3.10.2aS',
  '3.10.2S',
  '3.10.1S',
  '3.10.10S',
  '3.10.0S',
  '17.6.1',
  '17.5.1',
  '17.4.1',
  '17.3.1',
  '17.2.1',
  '16.9.2s',
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.4',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.5b',
  '16.6.5a',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.7',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1',
  '16.10.1s',
  '16.10.1g',
  '16.10.1f',
  '16.10.1e',
  '16.10.1d',
  '16.10.1c',
  '16.10.1b',
  '16.10.1a',
  '16.10.1',
  '16.1.3',
  '16.1.2',
  '16.1.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['nat']);
workaround_params = {'sip_agl_disabled' : 1};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvn65912',
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
