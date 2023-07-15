#TRUSTED 075c338574cb87c0d8b5e115acc44fd2595cf2f11dd7c2ae0fb4fdf2e6e5bbb9f8b94c8863b4bbfba6d69e1bb9b4acb85a2965a8186ecf74f851278661e04c8bd711cb75a394bccff3e58e87cc57cc0798ccfbb317fca50d36133a3148bb255d9b5146f7c87a7086446bef816c2f3f52ed9ed96f05f014b42db9f30fa165ecf919e7c026fca933a14de8c287ee6b06ac47251100b0d5f4df7dbb2156412ba43c90c1808b859ec8149d75b7a8312d6e67c6ca57f2ca539e60e8f2a128185979aac24374ac5f3da4afdbde83c9c0ced73b4254692fc94687c4e2723fb52578feea58c3b0e21e1d69d1459582951d75a2bdbaf8c8a728b479d5324ee965a2dbda420b2b22b28c660d44154da428c9fd484a0e1e7ba3ed83e8c5160279ffd486d1f27d3305007b1ea6b54b74a71da1b65c9b90f44db1a1801d3224e6d964bbd4847ae2d6769619f916648dba4bbf20c9396dd22c922557d096e285690d146046a5ffa9a197f1b5377ac93b00e97be04ac93c39e7451e816de913369ae728969556c638452c596ccb65d9b30556646e8cc731c9d6c4bab51b65822598b2353d63433394a24ea6d6832b487d2eaba21f4ece64555a06db5883716add8610864fdeb62cf7e59dbe9759698cd93133c900bc62c03801babc9f0cc0bab66e2be2b1d95a8f2b58d5776e8f750c70b0e6d012627012339c4c95b827760d52ffd8044c5f132e
#TRUST-RSA-SHA256 43bb2937ffe847e1df827c673c22483322c7e3b8c956f238f38109a2b9556d95be27ec15a062922e357ead3bec1fb7fee2b9bb62fbd86e096bd461d25e49815a74250666273a9c93c43333ac8760f16f064495761cee19e262964d1c7867cf7bfbd3e464d8b04faae02d346573d07d7e6e6b403309048589669ae49e0bf51568a1d50f05b4698e628878e8873c08bc57ca71ac405875e73f3c51628f8aec1825c99fca424afc47eda9d45daa7f5fe637f30cd5f2a3788327ff5910f7e530f835cb6c2260dff79e63ca56e6cb1ae253c062780763fa8add6d8efbe6119c7ec0cefd029ef26b15c7b069ffbbc7b621a8591efeb8b34c52dc0f86c1ef81b27dd871d55b758b0a96f06adac6be1b1425f96995dc6a894e9a4d218b9bea31ad76f6dd1550b705e0628c4ed2509394bf5e2635441f9728c0dfdd1e1643c8b288cb5f98062549be389a4b4878d7ee74da00cca05141090a84ea625a9e4372103af941ad4812d4d9f355124da2df57ed154bd89243f155303f1ea7c3c640f053a28c6da4ad59adbae22f2beec10d8e3176115433f466e202670272eecc4df957dc1e9d83badfa879edbf3aefa2bfd18745929c2966fbe4500ef85a9925239d416415b24666132059e9a06efa5ae7d3f84b9d2e6b62766adf6f7e9422187889d847a45df0b998c9f3f7c7f58dbd40137fb660231130f32eb1b5e0c6ee3423768d9035a6eb
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173250);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/06");

  script_cve_id("CVE-2023-20029");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb51779");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-priv-esc-sABD8hcU");
  script_xref(name:"IAVA", value:"2023-A-0157");

  script_name(english:"Cisco IOS XE Software Privilege Escalation (cisco-sa-iosxe-priv-esc-sABD8hcU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the Meraki onboarding feature of Cisco IOS XE Software could allow an authenticated,
    local attacker to gain root level privileges on an affected device. This vulnerability is due to
    insufficient memory protection in the Meraki onboarding feature of an affected device. An attacker could
    exploit this vulnerability by modifying the Meraki registration parameters. A successful exploit could
    allow the attacker to elevate privileges to root. (CVE-2023-20029)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-priv-esc-sABD8hcU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a2d6033");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-74842
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86953f38");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb51779");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwb51779");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20029");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);

# Vulnerable model list
if ('CATALYST' >!< model || model !~ "9200|9300")
    audit(AUDIT_HOST_NOT, 'affected');

var version_list=make_list(
  '17.7.1',
  '17.8.1'
);

var reporting = make_array(
  'port'          , product_info['port'],
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwb51779',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
