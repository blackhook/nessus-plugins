#TRUSTED 210117535ab63948e2418e8b7cf3e45cc1f1356ba05ef726d603f18fd78e2a7cbe0323a5fe85ce502035eac03d92d7cd0097d96e00b8b65387c75194dfa33d17bdf4242c895bb2cc1a5020ab1706a1d1371f8e2605fce9f8b959b909afce295ff8a29ca0016094bc9b12988d94293cd8c154e50d2676876df44604aa5066b55fa9dc53050b590152a4e75d10db55fff6cd8e43527ab72da1e388e9d922f42869c721f977e62158b834655bf10e542d93b467c5212e93a26ce8b2ead4be3898e44b47b156106a85d6d49dd52acee8a0d2f99eca9d80f22de8fd1b68072cdbbf3212ab91f25430d4025d02e48e53e3c4cc7f25df8f4afb9eba5ddcac24a7e8dfc655e35e60ea13d1800dcfda939026f0fb08e0d7c0880cc8f350352c56ab869604809017546f7c99b8dbfb897ff85d1933d2e257f9eeb474d20a1836035efc1329f3dd63c69649a82c3d40aacf9d78e1994ac388039a5f3df6e3daffb38b0589707e427dd217cd6b74651085e40670d8d55efefe66f798b6332d97bb0f632d5ce47487d80e8501952bf33de886d849b9a3afd51c46e8614e194c26d23d0d2f37fdc5e3d1e1ba967fdaa93997331252062765ad891a4d8e8e952bceb94b12fa2135b5f3bc6a4a44acf951186b8df69d4a09204617e91524b978a8b9e7918294509a4b4810b202a39642254c36e9139eac342616bfc852cbd8d7f863eaa016fadc0f
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142472);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2020-3409");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr83393");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs48147");
  script_xref(name:"CISCO-SA", value:"cisco-sa-profinet-J9QMCHPB");

  script_name(english:"Cisco IOS XE Software PROFINET DoS (cisco-sa-profinet-J9QMCHPB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS is affected by a denial of service vulnerability. An unauthenticated, 
adjacent attacker to cause an affected device to crash and reload, resulting in a denial of service (DoS) condition
on the device. Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-profinet-J9QMCHPB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cff4d72b");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr83393");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs48147");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr83393, CSCvs48147");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3409");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
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
  '16.10.1',
  '16.10.1e',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.12.1c',
  '16.12.1s',
  '16.12.2',
  '16.12.2s',
  '16.12.2t',
  '16.9.1',
  '16.9.1d',
  '17.1.1',
  '17.1.1s',
  '17.1.1t'
);

workarounds = make_list(CISCO_WORKAROUNDS['show_running-config']);
workaround_params = {'pat' : "(^|\n)\s*profinet($|\r\n)"};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr83393, CSCvs48147',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
