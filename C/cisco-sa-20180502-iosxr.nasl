#TRUSTED 6f421b1752bfc01853ce078c907ece6c0abf4c63fc5700f66929e106b3dd2b0c97c25722cdf61a6bd266992ee04ea9249cd625bcfcb94d7f85a555eeee0f68dce41eedc0664b96f9fb0dd573bed0f2152c7fa10d62f2efe4de93351f15d1fd35835cd088f620f913a1e3d71375c9e651a3b20f892e153240ce570a1179e104aaec43100f1194979ef7f99191a04bfc491006be02b3bfa9136ad8e56e62a628607ce4e851b33ac321c4a25df092ed2175b3975b1ec6ddd72e918d431c3190df28bb9c041690e7ffdc995b5fc64eb68d5c140461da8863eb6686146c1ba8eee41431de89a2e5c0d194f8cfb1e086e48e5e981f4418a225e8f95ca655444cf5d80cc16307d33e0b378ce60570985e60cee37e3dcaf49bd13ef81bc4504e40de53e0325a5811b3bb2e62990c309f2acb9617274f02af9f9eb80a13fc5c33e62a9ea3e77ac0799eb26d5090a09426547270e48aff05eebb1e38b5fd12def27c867038337c9bb3b94fef1beeacb06a93619d30f0ece2fa4de049510b942933fe6ab5f92e14436071e9d9cc4c6eeee09d00c05c4448f6d54fdcb97b4c23a9674bf6350c834590cb249db9e88ebc0dad4bfe9e29cdbec3b9915ed12383b70e04133777994324a34c98c253d6df3afd5a9cb856148edef4c55139a8e08d75685bea695d11db79d0be4ca3eceebe42b8316a4944d5b553ce9bd21896a0e7491e4371cfee96
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133265);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2018-0286");
  script_bugtraq_id(104083);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg95792");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180502-iosxr");

  script_name(english:"Cisco IOS XR Software netconf DoS (cisco-sa-20180502-iosxr)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is affected by a denial of service (DoS) vulnerability in
the netconf interface due to improper handling of malformed requests. An unauthenticated, remote attacker can exploit
this, by sending malicious requests to the affected software, in order to cause the targeted process to restart and a
DoS condition on the affected system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180502-iosxr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?940111af");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg95792");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvg95792");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0286");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/28");

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

version_list = make_list(
  '6.3.1',
  '6.3.2',
  '6.5.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvg95792'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
