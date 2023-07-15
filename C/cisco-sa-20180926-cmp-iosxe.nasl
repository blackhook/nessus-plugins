#TRUSTED 6f18e56727ae7414e6d170953d242719f1e86eaf3d43ed418c20a3b319d9d3ae46c0079ece6406ec5dc5b65a5ede12de7a500ba8eb005a2d76897a8a151ea38e9b87bc547f3a1f958b4e4bb5fa3cfb637a4e7413cfe31997511ccf5e88e0773f9ba2700bdec38bf0261c299f9cbca1b40484f4b453153d4a67e0586fee95c2b867b53a3be3704350bc3f06fa98f029664dbf23b37b716d87c664d2acdf6baf6130aaa3029dc21a52f2efe8ac128141da01f6fc33eba352bad10524f989497fa0f94170fc1a6b985f421a58f4c41c1e9f04c2934e98dc999f703498916da69a542bc1b56b9f252bb7ca82f9ae110f658ef6d5ecca52efd61f435a25483bea03e44e2826667a5a2222449945d65cf510bf9f7e04dc4909a0879e2596dd016830b9a32dd30c5aadf7e63b58ff16b6ff5a36657145c70f5cd63f398e7a70b2d757b9ca2a7974ac8cf6f84a83e65c48929a60994c5ccea5fd0f44e55a030a29cdcd1ea3bf59c7fd92bcbd4eb8d1f752ca6689fc385a0ad32f6d9cd911d7ee6474fe7bd4e1d542033221c5fe9a5293ee788d32541b9dc426d10878abf0018a36e70250c17652566f9669e2a4a4922536213f37bd2146aecadcc0ac4da01377bd3134379c04742b57976b14a4712fef304a99d40a1245ffc9b5b6cd04a66ebff73be21a5cfb769cbf2b52d8351470dbb9e6c95a69793f235df1ce6f139376590d3589a9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117945);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2018-0475");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg48576");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-cmp");

  script_name(english:"Cisco IOS XE Software Cluster Management Protocol DoS Vulnerability (cisco-sa-20180926-cmp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XE is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-cmp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a1a387f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg48576");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvg48576.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0475");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  "3.1.1SG",
  "3.1.0SG",
  "3.2.0SG",
  "3.2.1SG",
  "3.2.2SG",
  "3.2.3SG",
  "3.2.4SG",
  "3.2.5SG",
  "3.2.6SG",
  "3.2.7SG",
  "3.2.8SG",
  "3.2.9SG",
  "3.2.10SG",
  "3.2.11SG",
  "3.2.0XO",
  "3.3.0SG",
  "3.3.2SG",
  "3.3.1SG",
  "3.3.0XO",
  "3.3.1XO",
  "3.3.2XO",
  "3.4.0SG",
  "3.4.2SG",
  "3.4.1SG",
  "3.4.3SG",
  "3.4.4SG",
  "3.4.5SG",
  "3.4.6SG",
  "3.4.7SG",
  "3.4.8SG",
  "3.5.0E",
  "3.5.1E",
  "3.5.2E",
  "3.5.3E",
  "3.6.0E",
  "3.6.1E",
  "3.6.0aE",
  "3.6.0bE",
  "3.6.2aE",
  "3.6.2E",
  "3.6.3E",
  "3.6.4E",
  "3.6.5E",
  "3.6.6E",
  "3.6.5aE",
  "3.6.5bE",
  "3.6.7E",
  "3.6.7aE",
  "3.6.7bE",
  "3.3.0SQ",
  "3.3.1SQ",
  "3.4.0SQ",
  "3.4.1SQ",
  "3.7.0E",
  "3.7.1E",
  "3.7.2E",
  "3.7.3E",
  "3.7.4E",
  "3.7.5E",
  "3.5.0SQ",
  "3.5.1SQ",
  "3.5.2SQ",
  "3.5.3SQ",
  "3.5.4SQ",
  "3.5.5SQ",
  "3.5.6SQ",
  "3.5.7SQ",
  "3.5.8SQ",
  "3.8.0E",
  "3.8.1E",
  "3.8.2E",
  "3.8.3E",
  "3.8.4E",
  "3.8.5E",
  "3.8.5aE",
  "3.18.6SP",
  "3.9.0E",
  "3.9.1E",
  "3.9.2E",
  "3.9.2bE",
  "16.9.1h",
  "3.10.0E",
  "3.10.0cE"
);

workarounds = make_list(CISCO_WORKAROUNDS['cluster']);
workaround_params = {'is_member' : 1};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvg48576",
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
