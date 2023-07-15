#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155585);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/19");

  script_cve_id("CVE-2020-9646", "CVE-2020-9649", "CVE-2020-9650");

  script_name(english:"Adobe Media Encoder < 14.3 Multiple Vulnerabilities (APSB20-36)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Media Encoder installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Media Encoder installed on the remote Windows host is prior to 14.3. It is, therefore, affected 
by multiple vulnerabilities, as follows:

  - Adobe Media Encoder versions 14.2 and earlier have an out-of-bounds write vulnerability. Successful exploitation
    could lead to arbitrary code execution. (CVE-2020-9646, CVE-2020-9650)

  - Adobe Media Encoder versions 14.2 and earlier have an out-of-bounds read vulnerability. Successful exploitation
    could lead to information disclosure. (CVE-2020-9649)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/media-encoder/apsb20-36.html");
  script_set_attribute(attribute:"solution", value:
"Upgrace Adobe Media Encoder to version 14.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9650");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:media_encoder");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_media_encoder_win_installed.nbin");
  script_require_keys("installed_sw/Adobe Media Encoder", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Media Encoder', win_local:TRUE);
var constraints = [{'fixed_version' : '14.3'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
