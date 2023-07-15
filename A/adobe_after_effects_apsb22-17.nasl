#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/04/26. Deprecated by adobe_after_effects_apsb22-17_all.nasl.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158780);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/27");

  script_cve_id(
    "CVE-2022-24094",
    "CVE-2022-24095",
    "CVE-2022-24096",
    "CVE-2022-24097"
  );
  script_xref(name:"IAVA", value:"2022-A-0115-S");

  script_name(english:"Adobe After Effects < 18.4.5 / 22.0 < 22.2.1 Arbitrary Code Execution (APSB22-17) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe After Effects installed on the remote Windows host is prior to 18.4.5, or 22.x prior to 22.2.1. 
It is, therefore, affected by multiple stack-based buffer overflow flaws which could lead to arbitrary code execution
in the context of the current user.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.

This plugin has been deprecated by adobe_after_effects_apsb22-17_all.nasl.");
  # https://helpx.adobe.com/security/products/after_effects/apsb22-17.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?268879dc");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24097");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:after_effects");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("installed_sw/Adobe After Effects", "SMB/Registry/Enumerated");

  exit(0);
}

exit(0, 'This plugin has been deprecated. Use adobe_after_effects_apsb22-17_all.nasl instead.');

