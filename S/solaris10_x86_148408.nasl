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
  script_id(59236);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-0399", "CVE-2013-0400");

  script_name(english:"Solaris 10 (x86) : 148408-01 (deprecated)");
  script_summary(english:"Check for patch 148408-01");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Vulnerability in the Solaris component of Oracle Sun Products Suite
(subcomponent: Utility/Umount). Supported versions that are affected
are 9 and 10. Difficult to exploit vulnerability requiring logon to
Operating System plus additional login/authentication to component or
subcomponent. Successful attack of this vulnerability can escalate
attacker privileges resulting in unauthorized Operating System
takeover including arbitrary code execution.

Vulnerability in the Solaris component of Oracle Sun Products Suite
(subcomponent: Filesystem/cachefs). Supported versions that are
affected are 9 and 10. Difficult to exploit vulnerability requiring
logon to Operating System plus additional login/authentication to
component or subcomponent. Successful attack of this vulnerability can
escalate attacker privileges resulting in unauthorized Operating
System takeover including arbitrary code execution.

This plugin has been deprecated and either replaced with individual
148408 patch-revision plugins, or deemed non-security related."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/148408-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}

exit(0, "This plugin has been deprecated. Consult specific patch-revision plugins for patch 148408 instead.");
