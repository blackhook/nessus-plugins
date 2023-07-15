#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154730);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/20");

  script_cve_id(
    "CVE-2021-40777",
    "CVE-2021-40778",
    "CVE-2021-40779",
    "CVE-2021-40780",
    "CVE-2021-40781",
    "CVE-2021-40782",
    "CVE-2021-43013"
  );
  script_xref(name:"IAVA", value:"2021-A-0513-S");

  script_name(english:"Adobe Media Encoder < 15.4.2 / 22.0 Multiple Vulnerabilities (APSB21-99)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Media Encoder installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Media Encoder installed on the remote host is prior to 15.4.2. It is, therefore, affected by
multiple vulnerabilities. 

  - Adobe Media Encoder has multiple arbitrary code execution vulnerabilities, due to access of memory
    location after end of buffer. (CVE-2021-40777, CVE-2021-40779, CVE-2021-43013, CVE-2021-40780)

  - Adobe Media Encoder has multiple denial of service vulnerabilities, due to a null pointer dereference.
    (CVE-2021-40778, CVE-2021-40781, CVE-2021-40782)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/media-encoder/apsb21-99.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81c74bad");
  script_set_attribute(attribute:"solution", value:
"Upgrade Adobe Media Encoder to version 15.4.2, 22.0, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43013");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:media_encoder");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_media_encoder_win_installed.nbin", "adobe_media_encoder_mac_installed.nbin");
  script_require_keys("installed_sw/Adobe Media Encoder");

  exit(0);
}

include('vcf.inc');

var win_local = FALSE;

if (get_kb_item('SMB/Registry/Enumerated'))
  win_local = TRUE;

var app_info = vcf::get_app_info(app:'Adobe Media Encoder', win_local:win_local);
var constraints = [{'fixed_version': '15.4.2', 'fixed_display' : '15.4.2 / 22.0'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
