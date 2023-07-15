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
  script_id(22963);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-5423");

  script_name(english:"Solaris 10 (sparc) : 120879-08 (deprecated)");
  script_summary(english:"Check for patch 120879-08");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Sun Ray Core Services version 3.1 Patch Update.
Date this patch was last updated by Sun : Nov/26/08

This plugin has been deprecated and either replaced with individual
120879 patch-revision plugins, or deemed non-security related."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/120879-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}

exit(0, "This plugin has been deprecated. Consult specific patch-revision plugins for patch 120879 instead.");
