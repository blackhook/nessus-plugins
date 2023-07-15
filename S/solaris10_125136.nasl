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
  script_id(26984);
  script_version("1.33");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-0217", "CVE-2009-2625", "CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2674", "CVE-2009-2675", "CVE-2009-2676", "CVE-2009-3403", "CVE-2014-0429", "CVE-2014-0446", "CVE-2014-0451", "CVE-2014-0453", "CVE-2014-0457", "CVE-2014-0460", "CVE-2014-2398", "CVE-2014-2401", "CVE-2014-2412", "CVE-2014-2421", "CVE-2014-2427");

  script_name(english:"Solaris 10 (sparc) : 125136-97 (deprecated)");
  script_summary(english:"Check for patch 125136-97");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"JavaSE 6: update 101 patch (equivalent to.
Date this patch was last updated by Sun : Jul/13/15

This plugin has been deprecated and either replaced with individual
125136 patch-revision plugins, or deemed non-security related."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/125136-97"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}

exit(0, "This plugin has been deprecated. Consult specific patch-revision plugins for patch 125136 instead.");
