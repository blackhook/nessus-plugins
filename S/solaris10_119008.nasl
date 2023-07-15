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
  script_id(36851);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2005-2715");

  script_name(english:"Solaris 10 (sparc) : 119008-01 (deprecated)");
  script_summary(english:"Check for patch 119008-01");

  script_set_attribute(attribute:"synopsis", value:"This plugin has been deprecated.");
  script_set_attribute(
    attribute:"description",
    value:
"VERITAS NetBackup 6.0 Product Patch. Date this patch was last updated
by Sun : Nov/04/05

This plugin has been deprecated and either replaced with individual
119008 patch-revision plugins, or deemed non-security related."
  );
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/epmos/faces/DocContentDisplay?id=1682359.1");
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/business/theme.jsp?themeid=sun-support");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}

exit(0, "This plugin has been deprecated. Consult specific patch-revision plugins for patch 119008 instead.");
