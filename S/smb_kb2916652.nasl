#%NASL_MIN_LEVEL 70300
#%NASL_MIN_LEVEL 999999

# @DEPRECATED@
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(71265);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/28");

  script_name(english:"Improperly Issued Digital Certificates Could Allow Spoofing (Microsoft Security Advisory 2916652)");
  script_summary(english:"Checks if the relevant certs are blacklisted in the registry.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"This plugin has been deprecated."
  );
  script_set_attribute(attribute:"description", value:
"The remote host is missing either KB2677070 or KB2917500. If KB2677070
is installed, it is missing the latest auto-updates.

Note that this plugin checks that the updaters have actually updated
the disallowed CTL list, not that the KBs listed are installed. This
approach was taken since the KB2677070 automatic updater isn't
triggered unless software that relies on SSL in the Microsoft
Cryptography API is being actively used on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2916652");
  script_set_attribute(attribute:"solution", value:
"Ensure that the Microsoft automatic updater for revoked certificates
(KB2677070) is installed and running. Install KB2917500 if running
Windows XP or Windows Server 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2022 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_enum_qfes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/ProductName");
  script_require_ports(139, 445);

  exit(0);
}

exit(0, "This plugin has been deprecated. Use smb_kb2982792.nasl (plugin ID 76464) instead.");

