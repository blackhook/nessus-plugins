#TRUSTED b144c5962b416bcb2864a51faaa2d6e6b1d3cf6f53bbb7a21254a13a99d83ea8b5ddde5aceb51df754751e30800441e8e20aed4360ba133c2082e052068aa51ce4bddc3226456a3140799e588012ddd0c5fa64802451838a7d119744fd54f2a30a0c271c3d9ad1a167093a1eab9b7f1658c9bb52f745214e9bc45ba61e9b3c138a872b12c345918e65ed70765e0d096c646d947c0494507d8b001bc4555fb4d20ebd7d3e78244f77c038bd52af69089fbba0675717eb2b59fcb8084885e91548984e4e14d5b854b09170ee176ea2ac937e2a6ddb80b17c61e912c54fab2d3e9e28a63e5c99420acf4f53f13185795400a6dd7fee1ffc42e58d146eb589ca8a6b113d22735a3dab9f270022cb0443f3a7813ef1b3cffece6b3be4aa643afa666b8931406f07465b0c98a9a71de8f64a2715142c38d93a61e5aacafee8ac1c9b7de20f4d64525746a71c2a4c225e403393424b282a14b0238e9637d882462f87fb2d179ce7d27e41ac594cd9ce3e2b46218bd1f0ff0a60d5a582aa0b535d171bd45ee3ecf5359579d6474ab95ae80b991f79ddb7a8aeeca4b553360f4a2f3757438c43daecdc23cb677561f3cf35f7bcb6a0be222913b86afe86da23e6e87fb8d6b7f73e67a793cd0a19932989e7b4b534a94dfd9a110b39ece79d3e192e6f928030bb28ec053b4a5189ccb2f329980bfdc808d88031d73087e2d38de71494218f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133226);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2018-0418");
  script_bugtraq_id(105185);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj22858");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180815-asr-ptp-dos");

  script_name(english:"Cisco ASR 9000 Series Aggregation Services Routers Precision Time Protocol DoS (cisco-sa-20180815-asr-ptp-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is affected by a denial of service (DoS) vulnerability in
the Local Packet Transport Services (LPTS) feature set of Cisco ASR 9000 Series Aggregation Services Routers. This is
due to a lack of input and validation checking on certain Precision Time Protocol (PTP) ingress traffic to an affected
device. An unauthenticated, remote attacker can exploit this, by injecting malformed traffic into an affected device,
in order to cause the device to stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180815-asr-ptp-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d903f5a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj22858");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvj22858");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0418");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XR');

version_list = make_list('6.3.3');

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvj22858'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
