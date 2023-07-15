#TRUSTED 205f15b7a07d1582867b4263df486047feb17026855ef57fb4b4abe93d517f96312a9f8d87bf9dab84b702060eadc9ee6513493e7e46d7470d9b48545ce160a9657cdff946852619367c9c06286740b14452fad21d06ab2b4c6ddec0e9d3a52545170dbe90d7b197f382a5d33aea5383edc8204dfe74d4b7785815d28ef1d91c4a32b8fcdf1497967cead19c8a48dfe2c307e9623821811d87f0d63238841bd1daee71bf3b887643e873860d4fa0790718709297f0e9ec9a631146d1f82fd9e58652717397a5fdec5f1ea2679f1d59b51b1b6de6427ebef95f9f624191786ffe2b50480930c40624c1592c7f4d29e092c7b07636e7ef9f95bbcd122ae143a3d31e3029c8de955aa5d0260e1873a00ba466e0edf524e2f3034996e9e681112c3d396e0eb19c6da577d35a5aa991412874a15029be476d4d3042ca6f46df347e21c41afda077086b6a1ff94a70d74db3580b667dc0aeaa3a791d474a1c5bbc0c309051c893876d41f9f9d74c605452d06626ebc864a318200d17dd7be8b4f8b1a42b314248691af91c72b1471f0e0a67e41ef14b8e23f1a120cea1f94f36347c987065a2b18c0b85fc7f5baa411d4bacea5276004611006ebd54e2a47f9d9770ae12a74691d3133aeade38e4bf6bc5b24cb8b21e90798b72e5beca9c4f629f6df16491f48c0f56646a7a0cbf4ec2a7b79a089aab28a886ccf7e0cb4b02e7452232
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131728);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2018-0484");
  script_bugtraq_id(106560);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk37852");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190109-ios-ssh-vrf");

  script_name(english:"Cisco IOS XE Software Secure Shell Connection on VRF (cisco-sa-20190109-ios-ssh-vrf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the access control
logic of the Secure Shell (SSH) server due to a missing check in the SSH server. An authenticated, remote attacker can
exploit this, by providing valid credentials to access a device in order to open an SSH connection to an affected
device with a source address belonging to a VRF instance, despite the absence of the 'vrf-also' keyword in the
access-class configuration.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190109-ios-ssh-vrf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?efbc26fd");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk37852");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvk37852.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0484");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/06");

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
  '3.18.3bSP',
  '16.6.3',
  '16.6.4',
  '16.6.4s',
  '16.6.4a'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvk37852'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
