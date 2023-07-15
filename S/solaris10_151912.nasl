
#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2018/03/12. Deprecated and either replaced by
# individual patch-revision plugins, or has been deemed a
# non-security advisory.
#
include("compat.inc");

if (description)
{
  script_id(87640);
  script_version("2.12");
  script_cvs_date("Date: 2018/07/30 13:40:15");

  script_name(english:"Solaris 10 (sparc) : 151912-11 (deprecated)");
  script_summary(english:"Check for patch 151912-11");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"SunOS 5.10: OpenSSL 1.0.2 patch.
Date this patch was last updated by Sun : Jan/16/18

This plugin has been deprecated and either replaced with individual
151912 patch-revision plugins, or deemed non-security related."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/151912-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}

exit(0, "This plugin has been deprecated. Consult specific patch-revision plugins for patch 151912 instead.");
