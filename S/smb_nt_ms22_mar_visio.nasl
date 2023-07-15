#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2022/06/09. Deprecated by smb_nt_ms22_mar_visio_c2r.nasl.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158927);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id("CVE-2022-24461", "CVE-2022-24509", "CVE-2022-24510");

  script_name(english:"Security Updates for Microsoft Visio Products (March 2022) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated to be brought in line with Tenable's C2R plugin policy. Pleas use smb_nt_ms22_mar_visio_c2r.nasl instead.");
  # https://docs.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f54ed9ea");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24510");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_visio_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "SMB/Office/Visio/Installed");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

exit(0, 'This plugin has been deprecated. Use smb_nt_ms22_mar_visio_c2r.nasl instead.');
