#TRUSTED 8107f1e137b8819befdefc9c289e211fb810df303fe2a3656ec8bbd3240bfed42d3ce95a2f1502c17648f723a029734241bd2d8eaaab3ddca2caedea320dbaf53bd2349f07696f41db476f07771bf817334419ef236fd683f9a5c2842b2b21e556470706b95c5e0778e733f1dddd85b0ecc07829b41ad6ed2b2682c5955fbf9221136df398a4d937bfa8ff18ea010df3d0ba4a79d92495c9a284a9f00ef5a21605a756f9a610332848cff06f9cfb52115d82064a596de338ffdaf7130ef62a0366536d181dd4bed4d2e14a2eb9d5cd55e508f470f43bf6d17269a5e31752622a162f38d1875514486b31d3d6548dee12cdf081cc01096d66d3a8cd1de41d2be2ddb6b62f831e04f848f4650d31c35dcc9172b127738300aeafc9756bb2a4533bf76d2d32fb2632406eec487d38c36288b5027afc4ba15dd128194d01932bdefa4af2ce2dd3ef7383f613b0c86dd95175efd07a592f5021feeec0df1a66cd3f49ed753aa770265c22ff516515220e248f3cbf727fbdda76d078b5917e9775be897fe6f2c283f84d333a92899d8b537946dd039762a195622e19024bd424a5fa335af49011c38c3202d63bd3e164a24224a63b1486b6a2c78982c547a5202823652d3f08946465071374e2dc2b14c4d80ef576901d37a584622b41db53b2fa0c16a58057168fdb76ac1cefd2e1b2bf2b5f3c1dbc992373b0efc892828ed95d081d
#TRUST-RSA-SHA256 01745af14df2f43f9cd9738bbea021476624e60ec1990ffc82d6228f308b98d1d4fddeb95cfbe963e90642e6e0ebcea3449a75f495898a8d5e1811376c65345c467127f88bcaa9caa8e3830fdd7e48353b08682e6b6f654fa706b5891234abb8a12d1712e08654ca1a84fd90ca5aa70b56af4b37421fe688ec957b1825792b43617bfb1040e803b786af3b350bdee9615250b93a7ee54b0f2235f9403f887d35e340c5d0e4555f3d77fcadf4a708fe4fa5ea3b3addc6689524666eb897bf2774d035cbe7acfd19575a750321ae7c6e08f425d0ac0a910ba0dfb5cd2ee86035de755ffb27912788e54f0748b4dd45735c9e520e0088748ecffc2d65e8d63b5132482827f6dc87c3481561827579152f282f21d2ed48aa9ba1e2599b0e814b65fe61c1a095885fffd41f050a1e2c0e7924ea2d7a51a3b2d82ec9c2d5277957dabd75eadc61923e459ab401c6079ba220c7505a0cc2ea4bf739f05ee221a20007d76212064096e6fff3e623222a358dcc1224f5cfea456427d2f5e35d0d9a1d8f13ff7f8c0a5f2387bc562692dbc8dacd186116b65edb4163ab165a910d36fb2ae179e76e1b0363e199a3c0ba8d57cc638ef7c4d87b2b11f6f80ba12cbea8bf5bf46125c9394ddd4a8fbb29816ea64900920d7ef9bb30fd66db6dd7315fd51502a9a93f88ba202948e4c3b43f815e91d772241618a001e8b7d9f4bb1d976cbd113d
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108882);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-0167");
  script_bugtraq_id(103564);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo17183");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-lldp");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");

  script_name(english:"Cisco IOS XR Software Link Layer Discovery Protocol Buffer Overflow Vulnerabilities (cisco-sa-20180328-lldp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XR is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-lldp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b0c7a7a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuo17183");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCuo17183.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0167");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XR");

version_list = make_list(
  "5.2.0"
);

workarounds = make_list(CISCO_WORKAROUNDS['show_lldp']);
workaround_params = make_list();


reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCuo17183",
  'cmds'     , make_list("show lldp")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
