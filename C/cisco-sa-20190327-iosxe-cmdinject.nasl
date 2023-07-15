#TRUSTED 32f5078d7cbed1dbb5019fab0531d8fc512a7c6a3b5d4f5903751cb6c7a9b57f2bf0ff8876d7a9c826d28a788eb62748c68e3b71707160756407b6dc182d0213a77d184291728c9d5fa227e47740f2262be8abfc48d970dd5ef7a11b6f7d4c80b16718f271e144c6a460756ff3540ea666efe75f344818d68762e563bfffe26e38b06229da9e3b5b35216b02300b74b32b3f1c19b281b944fb89329ccc0ec01e21dd176920390e78c46ffe180df4af91f7da75018546b87dd4ca8231900c4766cce2e994777845ec93a4bd9f2fc38c0b6de83b3868fbdb28364d001c1b2fe6f762d67b7792c74292d0a1e7c5f56df887bf58ac010a6d105bb10c2c7649e856475c7162616f6a60d2b29142d35903fd6d160386e11645917f45baec4cfbc6e27679469c62e20aeb3f5593bf9fcc67c3d5a71775084556ab95331773d953c1eb5b0eae34b460eb3e6e415f70c5b8c1742e32e8c6907da68ebf621fcc972efa86ee7fd6b7cd2ffa6e975f129ddab7716f3aaae37695d0dc5a80230d95e1b66eea5368fcc7105887a24d37eeb32ac3fb9c640574f1f37291ee882d8460d64fd79dce4be7efc046b4061c36d64134a54ec6ec8f5c543fdb6157937968f3bf39dca854f38b160b01d7b74b0a5ad44d3b3c43b4eb8d57a86ec9f94da33532b3216aea4c6ba3910fcbb637f6c70a618cb0a7cae37d1fc54f98ae59fdd511e63cb674a6f1
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127913);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/05");

  script_cve_id("CVE-2019-1756");
  script_bugtraq_id(107598);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi36805");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-iosxe-cmdinject");

  script_name(english:"Cisco IOS XE Software Command Injection Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability that could allow
an authenticated, remote attacker to execute commands on the underlying Linux shell of an affected device with
root privileges.The vulnerability occurs because the affected software improperly sanitizes user-supplied input.
An attacker who has valid administrator access to an affected device could exploit this vulnerability by supplying
a username with a malicious payload in the web UI and subsequently making a request to a specific endpoint in the
web UI. A successful exploit could allow the attacker to run arbitrary commands as the root user, allowing complete
compromise of the system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-iosxe-cmdinject
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?248d1150");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi36805");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi36805");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1756");

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

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info, version_list, workarounds, workaround_params, reporting,

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.2.0JA',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1'
);

var workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
var workaround_params = make_list();

reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvi36805',
'cmds'     , make_list('show running-config')
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
