#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2020/03/12. Deprecated by smb_nt_ms20_mar_4551762.nasl.

include('compat.inc');

if (description)
{
  script_id(134420);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/12");

  script_cve_id("CVE-2020-0796");

  script_name(english:"Microsoft Windows SMBv3 Compression RCE (ADV200005)(CVE-2020-0796)(Deprecated)");
  script_summary(english:"Checks the Windows version and mitigative measures.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated due to an out-of-band patch being release by
the vendor. The suggested mitigation provided in ADV200005 is no longer
required. Plugin 134428 should be used instead to verify the patch is properly
applied.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200005
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?736703d3");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0796");

  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/11");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/WindowsVersionBuild");

  script_require_ports(139, 445);

  exit(0);
}

exit(0,'This plugin has been deprecated. Use smb_nt_ms20_mar_4551762.nasl (plugin ID 134428) instead.');

