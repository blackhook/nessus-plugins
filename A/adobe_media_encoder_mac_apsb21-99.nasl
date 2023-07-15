#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2022/01/13. Deprecated by adobe_media_encoder_apsb21-99.nasl.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154729);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/18");

  script_cve_id(
    "CVE-2021-40777",
    "CVE-2021-40778",
    "CVE-2021-40779",
    "CVE-2021-40780",
    "CVE-2021-40781",
    "CVE-2021-40782"
  );
  script_xref(name:"IAVA", value:"2021-A-0513-S");

  script_name(english:"Adobe Media Encoder < 22.0 Multiple Vulnerabilities (APSB21-99) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Media Encoder installed on the remote macOS host is prior to 22.0. It is, therefore, affected 
by multiple vulnerabilities. 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.

This plugin has been deprecated to combine the Windows and macOS checks into a single plugin. Use plugin ID 154730
instead.");
  # https://helpx.adobe.com/security/products/media-encoder/apsb21-99.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81c74bad");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40778");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:media_encoder");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_media_encoder_mac_installed.nbin");
  script_require_keys("installed_sw/Adobe Media Encoder");

  exit(0);
}

exit(0, 'This plugin has been deprecated. Use adobe_media_encoder_apsb21-99.nasl (plugin ID 154730) instead.');
