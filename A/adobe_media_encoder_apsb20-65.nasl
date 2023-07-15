#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141861);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/13");

  script_cve_id("CVE-2020-24423");
  script_xref(name:"IAVA", value:"2020-A-0492-S");

  script_name(english:"Adobe Media Encoder < 14.5 arbitrary code execution (APSB20-65)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Media Encoder installed on the remote host is affected by arbitrary code execution vulnerability (APSB20-65)");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Media Encoder installed on the remote host is prior to 14.5. It is, therefore, affected by
an uncontrolled search path vulnerability that could be exploited by a local unauthenticated attacker, leading to
an arbitrary code execution in the context of the current user. A local unauthenticated attacker that could result
in the context of the current user.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/media-encoder/APSB20-65.html");
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2020-24423");
  script_set_attribute(attribute:"solution", value:
"Upgrace Adobe Media Encoder to version 14.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24423");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:media_encoder");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_media_encoder_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Media Encoder");

  exit(0);
}

include('vcf.inc');

# Vulnerability is Windows-only
get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Adobe Media Encoder', win_local:TRUE);

constraints = [
  {'fixed_version' : '14.5' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
