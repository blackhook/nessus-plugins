#%NASL_MIN_LEVEL 70300

# @DEPRECATED@
#
# This script has been deprecated it duplicates solaris_138195.nasl.
#
# Disabled on 2014/09/03.
#

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77466);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_name(english:"Solaris 10 (sparc) : 138195-04");
  script_summary(english:"Check for patch 138195-04");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 138195-04"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Service Tags 1.0: patch for Solaris 10.
Date this patch was last updated by Sun : Mar/19/10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/138195-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}

# Deprecated.
exit(0, "This plugin duplicates plugin #44397 (solaris_138195.nasl).");
