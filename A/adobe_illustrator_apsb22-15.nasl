#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/04/26. Deprecated by adobe_illustrator_apsb22-15_all.nasl.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158733);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/27");

  script_cve_id("CVE-2022-23187");
  script_xref(name:"IAVA", value:"2022-A-0114-S");

  script_name(english:"Adobe Illustrator 26.x < 26.1.0 A Vulnerability (APSB22-15) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Illustrator installed on the remote Windows host is prior to 26.1.0. It is, therefore, affected by
a vulnerability as referenced in the apsb22-15 advisory.

  - Adobe Illustrator version 26.0.3 (and earlier) is affected by a buffer overflow vulnerability due to
    insecure handling of a crafted file, potentially resulting in arbitrary code execution in the context of
    the current user. Exploitation requires user interaction in that a victim must open a crafted file in
    Illustrator. (CVE-2022-23187)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.

This plugin has been deprecated by adobe_illustrator_apsb22-15_all.nasl.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/120.html");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/illustrator/apsb22-15.html");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23187");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(120);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:illustrator");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("SMB/Adobe Illustrator/Installed");

  exit(0);
}

exit(0, 'This plugin has been deprecated. Use adobe_illustrator_apsb22-15_all.nasl instead.');

