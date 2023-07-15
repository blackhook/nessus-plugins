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
  script_id(27077);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2009-0278", "CVE-2009-2625", "CVE-2011-5035");
  script_xref(name:"IAVT", value:"2009-T-0009-S");

  script_name(english:"Solaris 10 (x86) : 124673-20 (deprecated)");
  script_summary(english:"Check for patch 124673-20");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Vulnerability in the Oracle WebLogic Server component of Oracle Fusion
Middleware (subcomponent: Web Container). Supported versions that are
affected are 9.2.4, 10.0.2, 10.3.5, 10.3.6 and 12.1.1. Easily
exploitable vulnerability allows successful unauthenticated network
attacks via HTTP. Successful attack of this vulnerability can result
in unauthorized ability to cause a hang or frequently repeatable crash
(complete DOS) of Oracle WebLogic Server.

This plugin has been deprecated and either replaced with individual
124673 patch-revision plugins, or deemed non-security related."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/124673-20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2022 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}

exit(0, "This plugin has been deprecated. Consult specific patch-revision plugins for patch 124673 instead.");
