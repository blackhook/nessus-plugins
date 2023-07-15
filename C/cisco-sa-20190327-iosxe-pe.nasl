#TRUSTED 552287aeb46969a4ac1190eeb1ddfbcc2a5326faa07ea1e8a7a98ecf2062a0353c50aa0baf3b9519dde114aa7a4e1dc4b72b9b4f2523b740617b2f97da639c553f00bb0c0d45702c034f65e8f1fcee1083192e0d1e548f94cdfbfd1b74a6a09b97ca040a5924272a041b8be8c4b21d3b8f1f25599eee59cd82ea3d41ccc4987eea5242e50ebfd254815a621519c8d3f6f2f7bac8178e683f22d9f997510651d4cf2c0eb67e7f85582ef2401ed14d02d67a325abca926e859d8808e412dac2087eea402b163ffa5c39273440caacb0b603867a1be5132814ca4dbaa771f96462e7828d4f037a1289bd32031ff052a9aae8c837561439d69746bdcb8859b0b34daa3d36c663ad84e7d7bf8a0b64a684f5d9c210115b828ad52b08ab8fa540ede0166e6fb403d15e95620ef1f06ec9bc050eb50c2e66f1a87b11c5d27812eb874e8b5172997dbd926bc888fa384f802e8a76b34bbf0018a48f60cf894d318041c38391ac873abda68f6c00c0bd6fc9f3ae265e3abbbdfe19da4e27c31fbef6012794f705374816ea59c328a189fe6285de8986382543316bf9427a949d0691e1666075b3310f8e956481fc7fd72ac1c393fd824a4960065b43589828f4da1f271b49bdfec2c2ab4ffb75c554715b2f8f39ca7fcd109c3b52967170925fee9f46749bf20893b2865c0b7f1e9941c72e2fa2caccf655ae9a370e330159149b070dea6
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(127912);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/29");

  script_cve_id("CVE-2019-1753");
  script_bugtraq_id(107602);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi42203");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-iosxe-pe");

  script_name(english:"Cisco IOS XE Software Privilege Escalation Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by a vulnerability in the web UI of Cisco IOS XE Software, which could allow an authenticated but
unprivileged (level 1), remote attacker to run privileged Cisco IOS commands by using the web UI.The
vulnerability is due to a failure to validate and sanitize input in Web Services Management Agent (WSMA)
functions. An attacker could exploit this vulnerability by submitting a malicious payload to the affected
device's web UI. A successful exploit could allow the lower-privileged attacker to execute arbitrary commands
with higher privileges on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-iosxe-pe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?acb267e0");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi42203");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi42203");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1753");

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

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.7.1',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1s',
  '16.8.1c'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();


reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi42203'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
