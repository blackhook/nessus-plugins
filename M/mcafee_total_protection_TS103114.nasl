#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173646);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/29");

  script_cve_id(
    "CVE-2021-23873",
    "CVE-2021-23874",
    "CVE-2021-23875",
    "CVE-2021-23876"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"McAfee Total Protection < 16.0.30 Multiple Vulnerabilities (TS103114)");

  script_set_attribute(attribute:"synopsis", value:
"McAfee Total Protection installed on remote Windows host is affected by a multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of McAfee Total Protection installed on the remote Windows host is prior to 16.0.30. It is, therefore,
affected by multiple vulnerabilities, including the following:

  - Bypass Remote Procedure call in McAfee Total Protection (MTP) prior to 16.0.30 allows a local user to gain
    elevated privileges and perform arbitrary file modification as the SYSTEM user potentially causing Denial
    of Service via executing carefully constructed malware. (CVE-2021-23876)

  - Arbitrary Process Execution vulnerability in McAfee Total Protection (MTP) prior to 16.0.30 allows a local
    user to gain elevated privileges and execute arbitrary code bypassing MTP self-defense. (CVE-2021-23874)

  - Privilege Escalation vulnerability in McAfee Total Protection (MTP) prior to 16.0.30 allows a local user
    to gain elevated privileges and perform arbitrary file deletion as the SYSTEM user potentially causing
    Denial of Service via manipulating Junction link, after enumerating certain files, at a specific time.
    (CVE-2021-23873)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.mcafee.com/support/?articleId=TS103114&page=shell&shell=article-view
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?500a257f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Total Protection version 16.0.30 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23876");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:total_protection");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_total_protection_installed.nbin");
  script_require_keys("installed_sw/McAfee Total Protection", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::mcafee_mtp::get_app_info(app:'McAfee Total Protection', win_local:TRUE);

constraints = [
 { 'fixed_version' : '16.0.30' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
