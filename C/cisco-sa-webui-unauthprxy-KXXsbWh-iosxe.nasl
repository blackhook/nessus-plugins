#TRUSTED 072828f2e534e31e9441bd77e99cbe4ce67257c82a877ff81c69ceac546b55e86a438692e9b3251eee8f4b88392ac2635ecc15890d67d7237f85b171189c2d905608e27f565b3d8064667eba561bee5a1b06c6ea60d44c3915a316241c0bfd99922ce554e76726bda283c9745f7d1849a196d8048ab74e55a51295e0f48c4afcd56862ac84cddadd6ba46667d6e249026a0d145a7bbb4d70861684c0e8919c3a9b310e6340b5977353c08a4e621d5109ba973fb139015c151616a6fa0784930c0b29ca61d7b99f4d5b825cf5c1602973e5b0ba3295dc095165b1b168f43efce676e72e4bf5b317a3cedce827b07d68771bb04a9479709ce5b40c4930ee7bee45c30dcded7c6880a9247ab6f72688ea1e6a0d9956bfed96d8e3ba3db6953473e0067617923e6dd3c64b51c7b0763a321cb94b4280e4d769723adc145d03e0a5dd4623817ddf9eb700aaf325029006714a33e1b1877d8db67c3455f356507fcbc90db4fa944dc2d81cf8c4ee905245b2f6eed95835972ff9e2864b9340f5ae35e17ba7fb7f601e03ba654f6ebf1911738833eafe40548be7175bb3baa0305816f4b043b36a6ede534b5381200c79e0ceb031b4ee6c6a1d2a41ff8ddf85f3cb0734f2c5fed4507ef2d6f323c9619f44ac6904953cafa9cedc14eed86580f9d6c24f5d6d9cc0deac835d7183917d30aea6aa429fdbd0fc93a89a2c264c18f5ec5ab6
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139327);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3222");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq90862");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webui-unauthprxy-KXXsbWh");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Web UI Unauthenticated Proxy Service (cisco-sa-webui-unauthprxy-KXXsbWh)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a UI unauthenticated proxy service
vulnerability. The vulnerability is due to the presence of a proxy service at a specific endpoint of the web UI.
An attacker could exploit this vulnerability by connecting to the proxy service. An exploit could allow the attacker
to bypass access restrictions on the network by proxying their access request through the management network of the
affected device. As the proxy is reached over the management virtual routing and forwarding (VRF), this could reduce
the effectiveness of the bypass.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-unauthprxy-KXXsbWh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3014ccae");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq90862");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq90862");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3222");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(17);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.12.1y',
  '16.12.1w',
  '16.12.1t',
  '16.12.1s',
  '16.12.1c',
  '16.12.1a',
  '16.12.1',
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1',
  '16.10.2',
  '16.10.1s',
  '16.10.1g',
  '16.10.1f',
  '16.10.1e',
  '16.10.1d',
  '16.10.1c',
  '16.10.1b',
  '16.10.1a',
  '16.10.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq90862',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);