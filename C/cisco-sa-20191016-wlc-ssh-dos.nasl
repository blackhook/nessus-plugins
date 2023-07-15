#TRUSTED 38552bd53e76f8a8923e25a033ab145f86c32c7e625b514d31a3731688acc67deca0336d1ab1f814c2d03411e03ba39e0b8e4b6cc0f246c2626425dc24a064fb6390767bf9270927821d98787cda4ab4901568b7ef2216f4c57f2028404840897670d0c4cc2b1f3d74a67ca9beda5785f35f62aed68e254addb86f075751cb20dfe69aec10cf94ea25f7cae1f9268f155ed413110855c47c18a5b86eea17500f47fde4281622b385d9644dd3dcbc5c6be0f0f1e28d85c4d2099dc8b92519cbad42aab972bca3fbaf5e9f560cd4894d7c1de0c0cdc2f9257fbc19fffad3266d6d63ffcc590b37095ee81c1b8d851bf830c1e2a116b9dd8daf2814f0535bfd30d9a368c0ca66744942c3ea5ac842d3def6c4b9c1eb91e74028739f83db476169e891920392704f86632733658f2dbb0d75452aa1a1df61f8303eb2108cb616d263d3301c4bdf418bf933c379441b8e3fd8ae159dc0321f143f7e8f2a0ff8756d4001e5955c24414ffcd26a0b7b3c052b059478aeba528f5f7f71e2f95f8f993259e0123503b57f3e113f829ddb34af974728c3806ea6996c8c49dda856db51bb77c88afe698b659bd3b218cbf141d2c128cc686342c29ff0c67ee27d004f2129616c925dff31ee549f80d2c74908cfed8ef94fbc33ef60e8d821f509313b0db4ecf2865a9a00c94e4158ea4d153783b4cdeea059d362f69ce1f9a2b1217db5279a
#
# (C) Tenable Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(130208);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/20");

  script_cve_id("CVE-2019-15262");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp34148");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191016-wlc-ssh-dos");

  script_name(english:"Cisco Wireless LAN Controller Secure Shell (SSH) Denial of Service Vulnerability (cisco-sa-20191016-wlc-ssh-dos)");
  script_summary(english:"Checks version of Cisco Wireless LAN Controller");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Wireless LAN Controller (WLC) is affected by a denial of service (DoS)
vulnerability in its Secure Shell (SSH) component due to insufficient process cleanup. An authenticated, remote 
attacker can exploit this issue, by repeatedly initiating SSH connections, to exhaust system resources and cause the 
system to stop responding. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191016-wlc-ssh-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?728814ab");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp34148");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID 
  CSCvp34148");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15262");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_(wlc)");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp34148'
);

vuln_ranges = [{ 'min_ver' : '0.0', 'fix_ver' : '8.5.151.0' }];

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
