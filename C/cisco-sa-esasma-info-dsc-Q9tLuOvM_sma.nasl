#TRUSTED ad7f887210513272baf3128528576da77025387ecb85a26f41cfdee189ab1d89f7a3b6f9583fcb4a24642adf2cad9a8b3678179444e8dffb08c815b65cb1c5584857ce740c1410fcefe6dd43e2cd7464750c1981acb4b9f77ecbe25377833b9cc065542f30ce181f7d22ef8c2b25143b4ae6bb2880770ee80a239bda24c2ff1b98f03616a7c8416645ef6835a2daf25e7cf35fd28960316fd2299196e8f547998603e17bc94160819f23b624f6fc1746dfe1f190428f00c11cd0c29e060a563d7e40dc0c3e2ce46791b35b15c01693909635db146f71031747a157cf2e17b1699f08a2169c4489c3016d112f828991841d2b04a99ac10c7164e6db19a9f743cd3b72720401c754ebc650a363bc0d7058b77fe8255a9d6e80df1e6231b87b616cf08f983d5342aa263b8bb754bf7940b454139a35641878d21addd5d640775db3c0b06d8a5967659a0b4c6199cb8933a5ac58109c2a1b463a8c3fea79a3ea914d9a2357435708e39b938b4b1982e4acac766577d5b1fab74d457fe36f380f4d88e43def596d2476d5fd3f1ffe7533a62025c130f303c276daccf2f2a48fc931678716ab56285f4887069dce6d1b2dab4747174c5e8a5246d4688737bda96bdf70cb4bbe75ea314918e9ce483962ba1e0c3ceb0fcb20bf978ed16d0561c63cc7b8c300297e03fb782cefd6c6be271c9139217413891d984da06399ddc3fc09a4c7
#TRUST-RSA-SHA256 03766e99d1d92499b9ebe25f147ff939aef91effdeb06236cf67ee6430ea7fac7737ba8b0d7660d206c3d198f00b42fd67accea90f6266a442f076be50cd22b828ef3f324d2a15dfee77529cda2a0bdb4ed509953db4f4ff7441fced0c186e05adf801c9a71f4832fd207fbf23735300777a6a8312bc873d66fe5e4fe2d2a2dd5400d94fec0cb1efbc950c2d22e2fde6dc2b2e30fac2cffa6bcc7f1427e24b915a65c4350b77c0715348eb7e115200dce77443712bef3002a0991df7a0fde81e039ad9872b01e6acd07c499765e759fb69ee9ecbd033a0b7ecc270e61bbb33990ab4edae5db8de256696203d209dbf1e03df661177c16c600ba72cf89a9eb89afcb8970aaf84367521db31a9363b76254f92739eff57f52ab4c8d76b42cbb8da608cadbf7cef0f185495e3dd98d4e0a13ad5e085f685235b0a50c4ad7798e16d69d9e87c43a5b22a92e2a4c39cfe12932e3fd02ba720865240343bdecb05ed3747ea40cf4605ab7625b436715e389bd8a21c519ad0f0be32b57e8dd4e64ebcbb6bb70a5432f4d500bf42e46c20048bcb0f072e75f64cce1e3c044ceffcdd1b55f0c3458661c6287baff5490660eb57e3d98fb32f6d2359a23a9ffd3a63ac983472fdb380ef6601ffe230ff76c4aa5ede1b950422b814c88bf92663d12028fa1c10453981fe203d153026915f8770dcfd248291406d51adc85d4beb28634f228c
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162385);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/08");

  script_cve_id("CVE-2022-20664");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz20942");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz40090");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esasma-info-dsc-Q9tLuOvM");
  script_xref(name:"IAVA", value:"2022-A-0250-S");

  script_name(english:"Cisco Secure Email and Web Manager (SMA) Information Disclosure (cisco-sa-esasma-info-dsc-Q9tLuOvM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Email and Web Manager (SMA) is affected by an information
disclosure vulnerability in the web management interface. This could allow an authenticated, remote attacker to retrieve
sensitive information from a Lightweight Directory Access Protocol (LDAP) external authentication server connected to an
affected device. This vulnerability is due to a lack of proper input sanitization while querying the external
authentication server. An attacker could exploit this vulnerability by sending a crafted query through an external
authentication web page. A successful exploit could allow the attacker to gain access to sensitive information,
including user credentials from the external authentication server. To exploit this vulnerability, an attacker would
need valid operator-level (or higher) credentials.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esasma-info-dsc-Q9tLuOvM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4dcc8c49");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz20942");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz40090");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvz20942, CSCvz40090");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20664");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(497);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion", "Host/AsyncOS/Cisco Content Security Management Appliance/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Content Security Management Appliance (SMA)');

# We cannot test for LDAP or external authentication
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '13.6.2.090' },
  { 'min_ver' : '13.8', 'fix_ver' : '14.1.0.227' }
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_NOTE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvz20942, CSCvz40090',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
