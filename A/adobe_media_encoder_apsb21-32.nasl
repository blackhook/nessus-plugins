#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149447);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/20");

  script_cve_id("CVE-2021-28569");
  script_xref(name:"IAVA", value:"2021-A-0233-S");

  script_name(english:"Adobe Media Encoder < 15.2 Out-Of-Bounds Read (APSB21-32)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Media Encoder installed on the remote Windows host is affected by an out-of-bounds read vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Media Encoder installed on the remote Windows host is prior to 15.2. It is, therefore, affected 
by an out-of-bounds read vulnerability. An unauthenticated, remote attacker can exploit this, to escalate their 
privileges on an affected system.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/media-encoder/apsb21-32.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c778acc4");
  script_set_attribute(attribute:"solution", value:
"Upgrace Adobe Media Encoder to version 15.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28569");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:media_encoder");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
var constraints = [{'fixed_version' : '15.2'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
