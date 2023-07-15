#TRUSTED 908206f7f57661605b288afb69443e22953d6d71d5df4af24953c0d3a1a79ed8d26069b0437434a6af104bf60dea92c2cfd09eda8d3a11b1654d662af8ff503f74132d9f26173db8088c22a7296ea480fe62f7d2648ec7eae07e8fe1d86789c1f1e773952558f71bd6a4ba07ec2c2e7284e54f0c49c3450dcd4b1e776c194f823ef86972e4de3b0dc5ac37fa0be8bd9c8a75589bdc4203735b45525464dbbf9a4a6184eba35c2e4a12d17d2e5c9a5cba8aae7b3fc26c72db75e76861ca424684707df89fc5654492209d6cee3bac207051b368c2dd750027542cd6475e72a8703528dd20ee0a86c3cfe74dd0e7c89c48f20442f7afe81feead9f7a0cd7108feacbd416f461118f23bc577f7e1f8b89a30f7ebf8b170e5283e899448675a551d9e09ecf79a2833d5dc80bb31d087bf11a4c37d2d9ec151f767b0f05ccc12ae428a516ec5601681cbdf65b4a03cef02ba1635aacdaf9aeb1d332b238ddb7a80cd34b93c63cf4eb77019d7e045b983fd941aadb7049caf08499bea4d5a3035ad2df429d9c9f9afad4b6748edd37c88dd884d96e4058154fb5c5422d93eaefbb86240d5213550c8c791fe9c7a280582a244bcc0270ff2c24fdabe234444d6124afa211cff818fb6e09dc1be7e79bd701aad71e115978f982b4d15d627c0536cc387fc9b4369dd65928aa38ab2497ddf549b1faef6e3706bb1339160f9038be53a05b
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134108);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2019-12709");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo19278");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-xr-asr9k-privesc");

  script_name(english:"Cisco IOS XR Software for Cisco ASR 9000 VMAN CLI Privilege Escalation (cisco-sa-20190925-xr-asr9k-privesc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is affected by a privilege escalation vulnerability in a
CLI command related to the virtualization manager (VMAN) for Cisco ASR 9000 Series Aggregation Services Routers. This is
due to insufficient validation of arguments passed to a specific VMAN CLI command on an affected device. An
authenticated, local attacker can exploit this, by including malicious input as the argument of an affected command, in
order to run arbitrary commands on the underlying operating system with root privileges, which may lead to complete
system compromise.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-xr-asr9k-privesc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9a9770a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo19278");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo19278");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12709");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');

if ('ASR9' >!< product_info['model'])
  audit(AUDIT_HOST_NOT, 'affected');

vuln_ranges = [
  {'min_ver' : '5.1.0', 'fix_ver' : '6.5.3'},
  {'min_ver' : '6.6.0', 'fix_ver' : '6.6.2'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo19278'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  router_only:TRUE
);
