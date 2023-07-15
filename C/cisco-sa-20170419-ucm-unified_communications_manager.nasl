#TRUSTED 00fb213aa8c5f6be9159c0e101e0df9792ae2d3236e4dd76cbb8a3c4583d0cd192ba8afd076be8abd63a19416eb5020289d07bca00d5d44722248d83092ba4f34a4594013e2b4fb8c1d4cdbf0247af763b1b8e171d8cebcf0d4616ec125a83e9318a45ee4717f0e4325d64069a8241765814af6d1482930d4ac604c5fa95c23a9d7f48c22d18a7ef27924e0d3ee365fff1d7f0b76d1219ea98b1195046b3ffadd400511b7c39310b8eef5b391dd232bbf3c1ecefbe8f4e2650d3027aaafa5282e0fce0d7f1b1d794b45b32887b6aab6b4abdec7198b99eefe33757a83a4da3c5205fea001c65f5798fc93fbf13acc969894abded68d277ab4a607cf810b75f714365554b0154b46df02c474a3cdf6bcf5fa9a764b61f597fd77699390dd7cd4734837b4ec0f43f7b1d3026b6e92699f0f4a94a49234519098e777b18c65e1fa5c6c5e918fdc1667525b73c4afb750c079c316964ab968afc06305b97401722a5d42096f8884ba53bd1cd5b30c1f483066ef19799a4ac77ab602a0070f4bb7cb0eb8a88e94d2044b1fd62c22804d39d9181a126bc5053d4055b71f454180a0415f34a78b44af10fe6e9a7abb1dca9e888162215b946dc6888bedc45e098480e94341b123862ba562e67f94dc9fc26e728139ebf8b72240309037c3e9a889f5760280340454859486b86e81bad8d4dc33269930f9b261fc412c3b0f41ce6e04052
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103511);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-3808");
  script_bugtraq_id(97922);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz72455");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170419-ucm");

  script_name(english:"Cisco Unified Communications Manager Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Unified
Communications Manager is affected by one or more vulnerabilities.
Please see the included Cisco BIDs and the Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-ucm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2de6197");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz72455");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCuz72455.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3808");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");


product_info = cisco::get_product_info(name:"Cisco Unified Communications Manager");

version_list = make_list(
  "10.0.",
  "10.0.1.10000-12.",
  "10.5.",
  "10.5.1.98991-13.",
  "10.5.2.10000-5.",
  "10.5.1.99995-9.",
  "10.5.3.10000-9.",
  "10.5.0.98000-88.",
  "10.5.2.13900-9.",
  "10.5.2.12901-1.",
  "11.0.0.98000-225.",
  "11.0.1.10000-10.",
  "11.5.0.98000-480.",
  "11.5.0.",
  "11.5.0.98000-486.",
  "11.5.0.99838-4.",
  "11.5.1.2.",
  "11.5.1.10000-6.",
  "11.5.1.11007-2.",
  "11.5.1.12000-1."
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCuz72455"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
