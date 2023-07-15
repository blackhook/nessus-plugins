#TRUSTED af3e9865c72d41e4fd952897c2c4cbfbdb22ac71139c02bf85cfac1898c982a0010824356411a6b04f902068b06b895e0a94fb1180427a2b689190cd5e38061d10dc7951dfbdd9d81ffc8c3a1faae157fa6ef404cdfc07b9384396d447de5c67b193eb58b8dd2c83be790dc1c907812927d4edfa329e3bd2e85c1cf32fd39adf82d3f7ffad9068ee5ab5f6abe27ff8847e1dc84dd2e3f3d7b6fa019af6761b739cf253271941e09355fe4d8b4041e377692a84bd8b5a1ca8e070047ce5b81fcfa05bfd98b069c267eb6ab16311ac85a671f25de664e7a4b46c56712898160a4ce92dde4e4a581aebe079ddba8e93d98d8afeb787a8a91b71aed9e4819313de8c7949e99a4b9bc58b2d85bf03464aa9cf1f40763b5970dde6b2f09bfe4da64e56b8dc1d91f9cfc540ae78d33ad612a6d331903b1d5ba234eaff6e8a4876962796cc489fefdf92112c677476925df1f909c39dd0ddc3ec4536f619ff79b67c28e5e8822e21214b44aced46b0869cea994db8cf0c654c2ed68f407837932437ecf81f6ee139370a39c9f1774a76cd3b1212d30bbf3bc2597870685bb8f8d1ebf544e76fe4ceb40f471d49c651255b9de8f883328d870f76639330defdc446567a310d64a852a2f7640ceeb2b45801d5595ab9ceb2c5c06b2b75a1d50bf1addd8cc56f6d15244b7e82108696288f5c8ad92da155b864c3fd4ee16b7795ab1bda47a6
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134448);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/16");

  script_cve_id("CVE-2019-12700");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm92401");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-ftd-fpmc-dos");
  script_xref(name:"IAVA", value:"2019-A-0370");

  script_name(english:"Cisco FMC Software Pluggable Authentication Module DoS (cisco-sa-20191002-ftd-fpmc-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Management Center (FMC) Software is affected by a vulnerability
in the configuration of the Pluggable Authentication Module (PAM) due to improper resource management in the context
of user session management. An authenticated, remote attacker can exploit this, by connecting to an affected system and
performing many simultaneous successful Secure Shell (SSH) logins, in order to exhaust system resources and cause a
denial of service (DoS) condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-ftd-fpmc-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?481199e8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm92401");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvm92401");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12700");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_management_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower_mc/version");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Cisco Firepower Management Center', kb_ver:'Host/Cisco/firepower_mc/version');
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {'min_version': '0.0',   'fixed_version': '6.2.2.5'},
  {'min_version': '6.2.3', 'fixed_version': '6.2.3.7'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
