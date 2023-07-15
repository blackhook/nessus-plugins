#TRUSTED 5b00e97d062ace34cf69d4b503b3586b0faa0b02d72ebf2fa089890d5c0225c94c3ea42f78a33c0487f9b4d921701af382d82c2fad37cc82bc94d9b28b20eec8c3f2aee2d6c3251e2810add489490bc60265e2b31fd9a3a44d197025968f7dfe24655a73807e73dbeecf16d36c2ed3d6ac446b82d43f1af243945cfbfd2f48764f1c0950ed84f99e9b22a19f429919f20521300eb8aa6e49cbf38c2b91410a0b92115c15d239bed053110564a8b2795c1d1b2acbffe26dff73a0adb89c54218d8f73e0511c78f0de237cde6115d8955a07c9a9a64c4f34b8197678d3c02c52b0dd93272e6585ab3bbf10496164fa4361068d3e5400464d0d0afe81fb65d25e1ba2f67c4eb910f144cd07b9fbfebc020a51f49f9aff5469bbfa956da1a26f985927b583c90bc0e731ab00109e7e2b64e7bb666f93ada54d64be1394ab596930d5da0ab87d453b64d03cd4a3efddfef5a8eec4cfa29cae6fdb49dedabe7277c18f64e8e32798f44357f946dba5bb7a1296e28338db89675f41646b429a11753427f51126220bf56474c78fd7d80ee3db63ee3fd30f1fa6babc5c25ddb0427f9442a9276d404063de6b82e74aa2a5c387ebd607e13d420d3b101bdd147414cd7c02f5ebfa82d8297b285f78a8ebd40014ef2860424d97b447d33ed17db67470b0bb8ba9d45317e18cd1177b7d37c61c4a0948111b60d29cf5bd071ec711839284ca
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131397);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/06");

  script_cve_id("CVE-2018-0170");
  script_bugtraq_id(103560);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb86327");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-opendns-dos");

  script_name(english:"Cisco IOS XE Software with Cisco Umbrella Integration DoS (cisco-sa-20180328-opendns-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability in
the Cisco Umbrella Integration feature due to a logic error that exists when handling a malformed incoming packet,
leading to access to an internal data structure after it has been freed. An unauthenticated, remote attacker can exploit
this by sending crafted, malformed IP packets to an affected device in order to cause the device to reload and stop
responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-opendns-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc4bc5a8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb86327");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvb86327.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0170");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/29");

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

version_list = make_list(
  '3.2.0JA',
  '16.3.1',
  '16.3.2',
  '16.3.1a'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['umbrella_integration'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvb86327',
  'cmds'     , make_list('show opendns config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
