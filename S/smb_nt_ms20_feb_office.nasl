#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2022/06/09. Deprecated by smb_nt_ms20_fed_office_c2r.nasl.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133716);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id("CVE-2020-0696", "CVE-2020-0697", "CVE-2020-0759");

  script_name(english:"Security Updates for Microsoft Office Products (February 2020) (deprecated)");
script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated to be brought in line with Tenable's C2R plugin policy. Pleas use smb_nt_ms22_mar_visio_c2r.nasl instead.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0696
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c75b3fb");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0697
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?097c5011");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0759
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?002d43eb");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a security update to address this issue.

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic updates are enabled or open any office app and 
manually perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0759");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

exit(0, 'This plugin has been deprecated. Use smb_nt_ms22_mar_visio_c2r.nasl instead.');