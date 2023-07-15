#TRUSTED 6542123301096ee369cd9d8562058d770b97df35a23ad5d383183dc39c9b338077961f772c14268320e51cded23f12d66ce2555e693904a61b4e9b2645dcfb0663a2083d7c8fdf5ee45271b6bfcb9d6764258d4aeb5dc114faa6b281260e6405f300609c3fc8c9b4f8db75550c8e96aa71ef2a3dbd0cc654350a40d600b9c22f1b03453336ba28fa8560330aa0067a9be7a71137f1e27ec800bddeb689ef674de23616cc221439e8227efcd7b632db71aea90e6d0e66ef294b61709a157fd7ea122a85b1d2b889570fd08ae1659612cf9ab3f5c333874a1d2d99fc0424b1d2b37ef75217895a0e41c52870737fdaaeed0db5c6d912fb1b0aaed4aedbdc53d203b786f06fc7d0272d6f01c1ed4c6b156ecfccdbc9167e9eb7cb8fea41853b862183b17f0c9447866ef0767072b5319fd4d9aba6464cd966e9662432427f100c5eb62079b55a44b705331029eb6c190f276fda87538d0c66d2e48cee2159a5ab73b4e61d15d58197e080cce590f41a60dea76dcb0baad37d056d9978ca91c54418c5e4017ac35dbe7e1d44ab8ab278dae28c0fba8910dcfbfeba12fd7047e21bc060f4871854ee754d4878187fa5752364d556a99b62c99441a201b604f1ea79b114e022223fef179f4e1bb1814c20d313b591e11a23e0767cd74f71a5774fdcbd3be86c6e921badbe798fc087ee38a11ef9e25ace65288c1d7f42f10a190c0449
#TRUST-RSA-SHA256 71e112409e9e7ce970aaec2f507363c781fc78db5098ad4f8b3add77c847eb86b86c4ab745bf1499a3bb177e9245660b7db6c52e87d878bec5a6ea3879b9f2e25ab194bb0d5e36964fb9e3b8811a8282787128d2ed5ebcf9b2d4867334cc008ce99a2e3edd08a6837bb8a42a889fa1415199f0740a750e8a81a66ed1e93fad12432ca8cde242cb10439b556b534e744d3c9c302bf2060fbed0292635cdcc96edd01660fd6afdd12fc1126d8a7dcfec466ed4b88e04e83b261d4360d59be533e4836cfa1954bb7479ca2a9db74e746ecdc8030fbadc57f2cad88167cd6e85b8046fa146c0a73bd033b8d4d22401dba43251bb971ddf5ee46cf538efc6888c130f02245e894efe61e825c290cd9f318c998ef7ecccd068aab7ce1011e0b91677eda51c1d72972c64c17091074519838870e5cdd123d9eb67e94e1ec0895c28c5da15f2bcd2ab443a88fbfc7c31fdcf699b4c1aff06d6adc2b4d6b69ebad6bc7549b8758905ae95fa0109e06bf28ece911670baab2a9f201378e1d1cc8adc04b14ee20caf3c5b4973c053d1908d00551f103740c1582954230799a88e1a61684ce0f255950a9d0ea9aa8138943af58a6f3d8077e96e4dac8b6c9603136738b16d12f722603bdc7672113861c26b7b0c31becb56431cdaea33bf3391dfddbf983ec56fb27ba5af49df50c984a4ba18abf89ab10cbf514147595c5e7804ad2dc4d06f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133720);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-3120");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr15083");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200205-fxnxos-iosxr-cdp-dos");
  script_xref(name:"IAVA", value:"2020-A-0059");
  script_xref(name:"CEA-ID", value:"CEA-2020-0016");

  script_name(english:"Cisco FXOS Software Cisco Discovery Protocol Denial of Service Vulnerability (cisco-sa-20200205-fxnxos-iosxr-cdp-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FXOS Software is affected by a denial of service vulnerability
within the Cisco Discovery Protocol due to missing a check when processing protocol messages. An unauthenticated,
adjacent attacker can exploit this to cause the device to reboot.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200205-fxnxos-iosxr-cdp-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3303b2ba");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr15083");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr15083.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3120");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('vcf.inc');
include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

app_info = vcf::get_app_info(app:'FXOS');
product_info = make_array('model' , app_info['Model'], 'version' , app_info['version'], 'name', 'FXOS');

if(
  isnull(product_info['model']) ||
  product_info['model'] !~ "^(41|93)[0-9]{2}$"
)
  audit(AUDIT_HOST_NOT, 'affected');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '2.3.1.173'},
  {'min_ver' : '2.4',  'fix_ver': '2.5'},
  {'min_ver' : '2.6',  'fix_ver': '2.6.1.187'},
  {'min_ver' : '2.7',  'fix_ver': '2.7.1.106'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr15083',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
