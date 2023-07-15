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
  script_id(59916);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/28");

  script_xref(name:"MSKB", value:"2728973");

  script_name(english:"MS KB2728973: Unauthorized Digital Certificates Could Allow Spoofing");
  script_summary(english:"Checks if the relevant certs are blacklisted in the registry");

  script_set_attribute(
    attribute:"synopsis",
    value:
"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is missing KB2728973, which updates the system's SSL
certificate blacklist."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/2728973");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2728973");
  script_set_attribute(attribute:"solution", value:"Install Microsoft KB2728973.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2022 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/ProductName");
  script_require_ports(139, 445);

  exit(0);
}

exit(0, "This plugin has been deprecated. Use smb_kb2982792.nasl (plugin ID 76464) instead.");

