#TRUSTED 9c58e6c32729cf7fe22afcc9cd3f16af764b6ff3d4b996725e74ec5cc21184c2ac4ebe09fd528dfd4d3dbb566253c8fccd3d721d7391b02762154e43046b3a259d3e369c6f0d70e86247ba0f7cee25f3169f2d1aca4f5a19193e3006658c54e0bd10836907d9781c06984fef3fd613ffc29e030cd579723ba6e267b38bc18043ca7aa1da5b1df4b7cc748d0501ffc642c40a2700b11a4bc4189b6c41fd09e09922b8098fe5d9b7ac24d8b5c4e4d6f00a593208550c72c6d11373b5ebbfc8b7b9ed161a3763c43513d8a03aa0e22ba46cfa95f7e19b20f56f68f05df49265f8423e07927df755e3f05c1d3259e78e3641cde1c7586f6b99335c01567073c0926b50614f9295dce4fd8a9304dc83f15cb6f7e2bf24bdcca1b86a95c7aa8d91e159aefef243e8fadd3934afd6dbf70ee28d29d262ffeb451902be9e1d12c8d63c20b1153a7a44baee5a61f663e7d5477f698ec08cddb0c2cef3a5c727ae25b0efca460e22c1faacf6ce89cf4184526ddcdae6832614d792784e6f66dbeae211019f3484d23afc25fea6e4592a5c8c2f4785e8f60109cf4fab40a20ea424c0378dfcf6850673f8bdb58e0475514f0aa8a4dfac58f7821678acb69494dd8ea396b9089dae4bffc2cee3a401d80333cef96caca9ce7996fdcf413c10592c50c9ef268f6e1c58f516c69c670df027aa0d250118c6caa7fad32d5d5be2ea1db091e22fab
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128054);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2019-1909");
  script_bugtraq_id(109043);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo90073");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190703-iosxr-bgp-dos");

  script_name(english:"Cisco IOS XR Software Border Gateway Protocol Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XR Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190703-iosxr-bgp-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee4856c4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo90073");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo90073");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1909");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:"Cisco IOS XR");
if (report_paranoia < 2) audit(AUDIT_PARANOID);

vuln_ranges = [
  {'min_ver' : '6.0.0',  'fix_ver' : '6.6.2'},
  {'min_ver' : '7.0.0',  'fix_ver' : '7.0.1'},
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvo90073'
);

cisco::check_and_report(
    product_info:product_info,
    workarounds:workarounds,
    workaround_params:workaround_params,
    reporting:reporting,
    vuln_ranges:vuln_ranges
  );

