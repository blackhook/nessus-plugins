#TRUSTED 8e3f9b67abe67ed3bd79a2ed8e1335d3f4b82e17e89114399f3f37095466666d163bdbc83fe54484db9c7fe83c59dd9cd3d2d3ba2c7d986559832fa1eee55772b04dcce3b9e4428e9faa6f34abf78e672eb78b9cf2f44b10e8bdc1db4ababb4c7fef6be55db98d71f9f1e1381db92d28a13969ead0f3c1978a7136ae70ec0e60a1d77574e643bfb1cfb90aa87b1976a4e0a85a3aa8b03f82546c4b1df184e5e72902543fb67157d295e6a1b94a8850132e94baad0f503f0330393ad88e3330a3ecbebfa17159f458db6b20c362f08bafcde5eb56bc7c6babb5e0febfc7d7cb77bbfa223ca71f45ea39cae36d8bb40511e75271d39e9a7abeca73525e426f57e21a6e99c43dad28c9cb2bc5b284b5850eb6ece1ef28ccc137c7ea8489cca0346a014a324b4512d98ece73fe53b9d0782b13359db9988d90b48dcbeb561ed758cd6289931ec5b3e700eb53324bb26ac39a89ae720cbc2ebe41bc09e77c28dcee1695c70f2c30ca6423d9e7b16290d92b2ec09d4a92388de8074a3990228888a6f63834ab72e3f847e6d9b1656102cc9b3d830ae58ffb63006c1ba5f8505eaec48689ad21b789c7e8c8227e6747099c504b18de48f140c12d19a6cd1ba2e1674575828605c4cf0f34bd74372ced46b0642294a7c2970cdd8cc0519531be1d3e77aafb73e75c5bdbe42c357aacfb742d17dab270a4905ded006da48416edc5cb507d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127917);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-1754");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi36813");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-iosxe-privesc");

  script_name(english:"Cisco IOS XE Software Privilege Escalation Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by following vulnerability

  - A vulnerability in the authorization subsystem of Cisco
    IOS XE Software could allow an authenticated but
    unprivileged (level 1), remote attacker to run
    privileged Cisco IOS commands by using the web UI.The
    vulnerability is due to improper validation of user
    privileges of web UI users. An attacker could exploit
    this vulnerability by submitting a malicious payload to
    a specific endpoint in the web UI. A successful exploit
    could allow the lower-privileged attacker to execute
    arbitrary commands with higher privileges on the
    affected device. (CVE-2019-1754)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-iosxe-privesc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56dcafb4");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi36813");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvi36813");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1754");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list=make_list(
  "3.2.0JA",
  "16.9.1s",
  "16.9.1d",
  "16.9.1c",
  "16.9.1b",
  "16.8.2",
  "16.8.1s",
  "16.8.1e",
  "16.8.1d",
  "16.8.1c",
  "16.8.1b",
  "16.8.1a",
  "16.8.1",
  "16.7.1b",
  "16.7.1a",
  "16.7.1"
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvi36813'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
