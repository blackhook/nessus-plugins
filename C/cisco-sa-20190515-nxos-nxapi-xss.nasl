#TRUSTED 5ace9708a9d3b5f08102f970c11196386de7bb14c7ac27064290b1dd793146de20ff59f4785b28d21fdd99399b2e396ce72a724d1294b7260ff302fabbc72e084210655593daba1ebc8514d811dc2ac17a41b4953e26d36d834826a0ebbe20f73df10b8560f89ab6bcba61af99dc283d25b7db5c7174095079718af722e7d1f8780151b4216a53a47e8c33b9325dd81edc7e8fd177f5362c425376a8f2d9888fa47fdff93621112069fd9429c08b73d900998d8de8fa22d3ba3c7e088414ffc5d6677cf0c105a8e7e3ac9b412e71624f4af01640188f17dd638f799c3d8642679b9ab12856527f2e757db73fd4dfe9864fa0586225703351e2c2b94ac91a8978669324a4f1203cd731b1cf7c56ae4902eca95fbc32419586b0f7bb6e068125b114c63712db2e011a5b8e43df4668f940c74baae2e9ed91259d9c97b92c204e2034d010e269bfb24b6f08ae628f3a1eeae9e9dbefbb2485deb1d50e0aa835a02f01c38cd685f9ea31e8e398fad89ac6fde05fada9ee07775913a7f7da6d1851133481e0919ef39fbde501cce3c801ee77dbe08d2d6ac70c8990a840b5c9774c15408c93a266ede3e230f5c1b06a97ba89745aa3ed3d0b08a163a00df40ce6bd296691b15626629367bb7c6c2d3eb462eb7ac5adf43c637624cbf207055b274695d16054957c906fcf179b5e1a9e8177b95a066ae88c2fabaa89a1b5aae25e8489
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125679);
  script_version("1.6");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-1733");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj14814");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-nxapi-xss");
  script_xref(name:"IAVA", value:"2019-A-0173");

  script_name(english:"Cisco NX-OS Software NX-API Sandbox Cross-Site Scripting Vulnerability");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by following a vulnerability in the NX API
(NX-API) Sandbox interface for Cisco NX-OS Software could allow an authenticated, remote attacker to conduct a
cross-site scripting (XSS) attack against a user of the NX-API Sandbox interface of an affected device.The vulnerability
is due to insufficient validation of user-supplied input by the NX-API Sandbox interface. An attacker could exploit this
vulnerability by persuading a user of the NX-API Sandbox interface to click a crafted link. A successful exploit could
allow the attacker to execute arbitrary script code in the context of the affected NX-API Sandbox interface.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # http://tools.cisco.com/security/center/content/CiscoAppliedMitigationBulletin/cisco-amb-20060922-understanding-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1596bcb6");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-nxapi-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?438c9559");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj14814");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvj14814");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1733");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);


  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco NX-OS Software");

if ('Nexus' >!< product_info.device ||
    (product_info.model !~ '^3[05][0-9][0-9]' &&
    product_info.model !~ '^90[0-9][0-9]'))
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  "7.0(3)I4(8)",
  "7.0(3)I4(4)",
  "7.0(3)I4(3)",
  "7.0(3)I4(2)",
  "7.0(3)I4(1)",
  "7.0(3)I3(1)",
  "7.0(3)I2(5)",
  "7.0(3)I2(4)",
  "7.0(3)I2(3)",
  "7.0(3)I2(2e)",
  "7.0(3)I2(2d)",
  "7.0(3)I2(2c)",
  "7.0(3)I2(2b)",
  "7.0(3)I2(2a)",
  "7.0(3)I2(2)",
  "7.0(3)I2(1a)",
  "7.0(3)I2(1)",
  "7.0(3)I1(3b)",
  "7.0(3)I1(3a)",
  "7.0(3)I1(3)",
  "7.0(3)I1(2)",
  "7.0(3)I1(1b)",
  "7.0(3)I1(1a)",
  "7.0(3)I1(1)",
  "7.0(3)F3(5)",
  "7.0(3)F3(4)",
  "7.0(3)F3(3c)",
  "7.0(3)F3(3b)",
  "7.0(3)F3(3a)",
  "7.0(3)F3(3)",
  "7.0(3)F3(2)",
  "7.0(3)F3(1)",
  "7.0(3)F2(2)",
  "7.0(3)F2(1)",
  "7.0(3)F1(1)",
  "7.0(3)",
  "7.0(2)N1(1a)",
  "7.0(2)N1(1)",
  "7.0(2)I2(2c)",
  "7.0(1)N1(3)",
  "7.0(1)N1(1)",
  "7.0(0)N1(1)"
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_NOTE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvj14814'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list, switch_only:TRUE);
