#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2018/03/12. Deprecated and either replaced by
# individual patch-revision plugins, or has been deemed a
# non-security advisory.
#
include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(34789);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_name(english:"Solaris 10 (sparc) : 137137-09 (deprecated)");
  script_summary(english:"Check for patch 137137-09");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"SunOS 5.10: kernel patch.
Date this patch was last updated by Sun : Nov/10/08

This plugin has been deprecated and either replaced with individual
137137 patch-revision plugins, or deemed non-security related."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/137137-09"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}

exit(0, "This plugin has been deprecated. Consult specific patch-revision plugins for patch 137137 instead.");
