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
  script_id(22976);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-5009");

  script_name(english:"Solaris 10 (x86) : 108670-21 (deprecated)");
  script_summary(english:"Check for patch 108670-21");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Solstice X.25 9.2 patch_x86.
Date this patch was last updated by Sun : Nov/04/08

This plugin has been deprecated and either replaced with individual
108670 patch-revision plugins, or deemed non-security related."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/108670-21"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:N/A:C");
  script_cwe_id(362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}

exit(0, "This plugin has been deprecated. Consult specific patch-revision plugins for patch 108670 instead.");
