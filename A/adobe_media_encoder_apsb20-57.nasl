#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140728);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/23");

  script_cve_id("CVE-2020-9739", "CVE-2020-9744", "CVE-2020-9745");
  script_xref(name:"IAVA", value:"2020-A-0427-S");

  script_name(english:"Adobe Media Encoder < 14.4 Out-of-Bounds Read (APSB20-57)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Media Encoder installed on the remote host is affected by multiple out-of-bounds read errors (APSB20-57)");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Media Encoder installed on the remote host is prior to 14.4. It is, therefore, affected by
multiple out-of-bounds read errors that could be exploited to read past the end of an allocated buffer, possibly
resulting in a crash or disclosure of sensitive information from other memory locations. User interaction is required to
exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/media-encoder/apsb20-57.html");
  script_set_attribute(attribute:"solution", value:
"Upgrace Adobe Media Encoder to version 14.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9745");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:media_encoder");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_media_encoder_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Media Encoder");

  exit(0);
}

include('vcf.inc');

# Vulnerability is Windows-only
get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Adobe Media Encoder', win_local:TRUE);

constraints = [
  { 'min_version' : '0', 'max_version' : '14.3.2', 'fixed_version' : '14.4' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
