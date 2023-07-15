#TRUSTED abb548ba016462b440794620283d6ca1e0a29298cab2bdc6b84bb2c7bdc9bac79c536a4bc2cd0cfb616b7e981ecb089d64fb5ed72a94d1b2d4a1b91832cb2d1310f33d50243fe53838e4d8d18189aff48f3eaca6db027da3c927b5e511b0b4cde9a15b874775bee551da040c016cd9b8ce55fdb14aab202573d7128deb621baf37bde444a24fbe022f6b509c8454f9cebf2e6299fdf5a8704555bcacf9075ee04dd55334695d9649de1a9286c9783b442ca37ab31ad696d67b1258a5028df33da6bf48aa0b7d44ca649b06b6c30fbdce5315b5ce0de8f71ae62a939d9bec317dc5ce4a93cdf85511c101246cbd3acf50749cf6be5e896f87e74cccafa91cd9312de423c45c84515437fb9f9a499a4553ac9c40476814acb0e7ceda83bdb16929d9ba5175255ceb31193f62e57fa8e35fe7a4d9ace81a080a0423d0150479e9385a7b16252a8c30f8cd9cd3c5603d1f854e8053290dacb0b4a0f32e48cf1383dc1000719572c81c5d2652e5933f743f31338e95b934c5291ebeab86072b6727e3eb45271955ec94fca444e7ec0a1e08daf4054a168ca4ab57bb637857081d77e7718c35dcec4b45d9247e52c5b4a7f64775a0a45bea5eb69f8f629104b1313cf9ee61362586a922b6888f770d7860b340bbed4a66f75cf442032e244df9ca9a70bca18f1f7707e9b51389128d9f5af53a0e9afb97e4d71fbbb2cd420747edbe6f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103676);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2017-12228");
  script_bugtraq_id(101065);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc33171");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170927-pnp");

  script_name(english:"Cisco IOS XE Software Plug-and-Play PKI API Certificate Validation Vulnerability");
  script_summary(english:"Checks the Cisco IOS XE Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE Software is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170927-pnp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d9fc170");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc33171");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvc33171.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12228");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  "16.1.1",
  "16.1.2",
  "16.1.3",
  "16.1.3a",
  "16.1.4",
  "16.2.1",
  "16.2.2",
  "16.2.2a",
  "16.2.3",
  "16.3.1",
  "16.3.1a",
  "16.3.2",
  "16.4.1",
  "3.10.0S",
  "3.10.1S",
  "3.10.1xbS",
  "3.10.2S",
  "3.10.2tS",
  "3.10.3S",
  "3.10.4S",
  "3.10.5S",
  "3.10.6S",
  "3.10.7S",
  "3.10.8S",
  "3.10.8aS",
  "3.10.9S",
  "3.11.0S",
  "3.11.1S",
  "3.11.2S",
  "3.11.3S",
  "3.11.4S",
  "3.12.0S",
  "3.12.0aS",
  "3.12.1S",
  "3.12.2S",
  "3.12.3S",
  "3.12.4S",
  "3.13.0S",
  "3.13.0aS",
  "3.13.1S",
  "3.13.2S",
  "3.13.2aS",
  "3.13.3S",
  "3.13.4S",
  "3.13.5S",
  "3.13.5aS",
  "3.13.6S",
  "3.13.6aS",
  "3.13.7S",
  "3.13.7aS",
  "3.14.0S",
  "3.14.1S",
  "3.14.2S",
  "3.14.3S",
  "3.14.4S",
  "3.15.0S",
  "3.15.1S",
  "3.15.1cS",
  "3.15.2S",
  "3.15.3S",
  "3.15.4S",
  "3.16.0S",
  "3.16.0cS",
  "3.16.1S",
  "3.16.1aS",
  "3.16.2S",
  "3.16.2aS",
  "3.16.2bS",
  "3.16.3S",
  "3.16.3aS",
  "3.16.4S",
  "3.16.4aS",
  "3.16.4bS",
  "3.16.4dS",
  "3.16.5S",
  "3.17.0S",
  "3.17.1S",
  "3.17.1aS",
  "3.17.3S",
  "3.18.0S",
  "3.18.0SP",
  "3.18.0aS",
  "3.18.1S",
  "3.18.1SP",
  "3.18.1aSP",
  "3.18.1bSP",
  "3.18.1cSP",
  "3.18.2S",
  "3.18.2SP",
  "3.18.3vS",
  "3.3.0XO",
  "3.3.1XO",
  "3.3.2XO",
  "3.5.0E",
  "3.5.1E",
  "3.5.2E",
  "3.5.3E",
  "3.6.0E",
  "3.6.0S",
  "3.6.1E",
  "3.6.1S",
  "3.6.2E",
  "3.6.2S",
  "3.6.2aE",
  "3.6.3E",
  "3.6.4E",
  "3.6.5E",
  "3.6.5aE",
  "3.6.5bE",
  "3.6.6E",
  "3.7.0E",
  "3.7.0S",
  "3.7.0bS",
  "3.7.1E",
  "3.7.1S",
  "3.7.1aS",
  "3.7.2E",
  "3.7.2S",
  "3.7.2tS",
  "3.7.3E",
  "3.7.3S",
  "3.7.4E",
  "3.7.4S",
  "3.7.4aS",
  "3.7.5E",
  "3.7.5S",
  "3.7.6S",
  "3.7.7S",
  "3.8.0E",
  "3.8.0EX",
  "3.8.0S",
  "3.8.1E",
  "3.8.1S",
  "3.8.2E",
  "3.8.2S",
  "3.8.3E",
  "3.8.4E",
  "3.9.0E",
  "3.9.0S",
  "3.9.0aS",
  "3.9.1E",
  "3.9.1S",
  "3.9.1aS",
  "3.9.2S"
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['show_pnp_profile'];


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvc33171',
  'cmds'     , make_list('show pnp profile')
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
