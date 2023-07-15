#%NASL_MIN_LEVEL 70300
#%NASL_MIN_LEVEL 999999

#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2016/02/29. Deprecated by smb_kb3097966.nasl.

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(82075);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/28");

  script_xref(name:"MSKB", value:"3050995");

  script_name(english:"MS KB3050995: Improperly Issued Digital Certificates Could Allow Spoofing (deprecated)");
  script_summary(english:"Checks if the relevant certs are blacklisted in the registry.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing KB3050995, KB2677070 (automatic updater),
or the latest disallowed certificate update using KB2813430 (manual
updater). If KB2677070 has been installed, it has not yet obtained the
latest auto-updates.

Note that this plugin checks that the updaters have actually updated
the disallowed CTL list, not that the KBs listed are installed. This
approach was taken since the KB2677070 automatic updater isn't
triggered unless software that relies on SSL in the Microsoft
Cryptography API is being actively used on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/3050995");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/en-us/kb/3050995");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/en-us/kb/2677070");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/2813430");
  script_set_attribute(attribute:"solution", value:
"If using Windows Server 2003, run the updater listed on KB3050995;
otherwise, ensure that the Microsoft automatic updater for revoked
certificates is installed and running.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2022 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_enum_qfes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/ProductName");
  script_require_ports(139, 445);

  exit(0);
}

exit(0, "This plugin has been deprecated. Use smb_kb3097617.nasl (plugin ID 87875) instead.");

