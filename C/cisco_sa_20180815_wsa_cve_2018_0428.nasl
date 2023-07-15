#TRUSTED 64de16b8f0df1e0ab816a93b8bc9b9565ba004d6dea8d9986eb4f455869a9795d8368ce63339430b1d284328b26f79a538a103bc0c39bf75cb74bc92b93617a385b6441fecf1edcbcf79696855352e86118ccf6955b3126883513bb0a468b630072aeec6e55370369606ef75be38e63ec21155fbaca1a906057efba0d0ebeaa1576af51d156d4098fb5411b6ce342fe25cf07733742d7b041e0da84f208892b5d9d3589b1c72162bac0176415fd55f45134eb3cfd34f63d4243499a4165be1d4b16e146d46bf1f1fd2a5cfcb22c32847d43663d587708ae7895795d08c1a5db9e5ff569904957965bfb842a1f88905b1490f01f84a3cca6e2763b497c42ddb4b158b392932fd66f1c72fd9fc42c06147a70ac78aa945e796d41e5c4938aa1d750c44adfcc963c3a92afd6b56eca4d76a1c613149e4da8d03406e9bd7efb6796267e50e4075d456d9d83595723a0aaf9828fe6ac481a1f84d721116018a9da7a18ea1cc43c8a425c1c609a89715224c6d3be87e35281fc1b32cbc6222adbce5b72d379023128beedb077b53d65ec7d1b560551966cb72f502e34a18c4589892ce62719089bfc8af81e484581cbed4dc002fa7d6b8b659576a226dd4a923f17b84d00a302ced094ffc3f42defeb7c41a57ff13353eba40215486b8304111b2a4206ba177fa06792e54d7044e5a39ffa95339bdc9a0cee245e4b77447e8e2154090
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112122);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/14");

  script_cve_id("CVE-2018-0428");
  script_bugtraq_id(105104);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj93548");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180815-wsa-escalation");

  script_name(english:"Cisco Web Security Appliance Privilege Escalation Vulnerability.");
  script_summary(english:"Checks the WSA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote security appliance may be affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Web Security
Appliance (WSA) running on the remote host may be affected by privilege escalation vulnerability.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180815-wsa-escalation
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87dd52c9");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj93548
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9bd6384");
  script_set_attribute(attribute:"solution", value:
"Apply the vendor supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0428");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");


  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion");

  exit(0);
}


include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");


product_info = cisco::get_product_info(name:"Cisco Web Security Appliance (WSA)");
workarounds = make_list(CISCO_WORKAROUNDS["no_workaround"]);
workaround_params = make_list();

# 11.0.0-FCS-250, 11.5.0-FCS-000, WSA10.0.0-959, WSA10.5.0-FCS-000
vuln_versions = make_list(
  "11.0.0.250",
  "11.5.0.0",
  "10.0.0.959",
  "10.5.0.0");

reporting = make_array(
  "port"     , 0,
  "severity" , SECURITY_HOLE,
  'bug_id'   , "CSCvj93548",
  "version"  , product_info["display_version"],
  "fix"      , "See advisory"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:vuln_versions);
