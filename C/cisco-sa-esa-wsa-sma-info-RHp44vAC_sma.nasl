#TRUSTED 4c508d959032887bcbd0c8a9131ef88eb86d12263579c2ea6265b61f61a52c59f65b05765c752276204b1a076fcc1775b6ea163e28d0530b60d7613dbfb34636ca2f945946c894899b2e8a421673cc9a44ef259d7e7a19b6506aeee66ef9121841a25c5b59418cd5c2efd2ccf2c1b7ec247e1c3863b0827337a3a318391463bc7e00f19c018f6010548d8bc82d79b0a6cceb75c457a8b968d7a6b607d4130703187e5475282740ac5f9625faf7f4e1d12543d43c93f6dd9b5ad75ffc8a0407d6f9ee3464bc129e0b251b92b6a565163ac9fe9bd744c15c0710593ad89aa26609b33e70f26bfc6e03eb917ac1e4c4447c97ef5a19c2b72dd662c981d781470e10d4b51a605617c6949fd7f76e50a019a522f97a28996a4d3d61952fdbf0923547e62b898bec4fc97c2f6e9960a9697bedbdba744f49f28e6cd77d150cbda1bec59a60b7bb9c009857790628fa17e853d471126ca42c2d08293805809177007a6de0436770db3b3da97c8de8f5c9b0c2f80a7c5ab4de892db52d1ab727724499f5dc456e2913cf6a4358b8a6da7d5b006dcaa6dbfde664059d99b33d979b1375ddf7eed06c72ae6feb9be83f3a71cd5052f23b1f095bd75c11fc5a19aa56ab884db0b7845633c3759495f96548dc70be71b7f06804e338c31ed5b21a6f8122fe0275c3d589665aa6adcac6df76f52f26ca1b8831f07465463d9df6c1df2e1f9e71
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145554);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/29");

  script_cve_id("CVE-2021-1129");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu93201");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-wsa-sma-info-RHp44vAC");
  script_xref(name:"IAVA", value:"2021-A-0050");

  script_name(english:"Cisco Content Security Management Appliance Information Disclosure (cisco-sa-esa-wsa-sma-info-RHp44vAC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Content Security Management Appliance (SMA) is affected by a
vulnerability in the authentication for the general purpose APIs due to the absence of a secure authentication token
requirement when authenticating to the general purpose API. An unauthenticated, remote attacker can exploit this, by
sending a crafted API request, in order to obtain certain configuration information from an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-wsa-sma-info-RHp44vAC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1adca350");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu93201");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu93201");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1129");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(201);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion", "Host/AsyncOS/Cisco Content Security Management Appliance/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Content Security Management Appliance (SMA)');

vuln_list = [{'min_ver' : '12.5' , 'fix_ver' : '13.8.0'}];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu93201',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_list
);

