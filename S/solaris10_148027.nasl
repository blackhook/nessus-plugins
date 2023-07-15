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
  script_id(64656);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-0411", "CVE-2013-0412");

  script_name(english:"Solaris 10 (sparc) : 148027-03 (deprecated)");
  script_summary(english:"Check for patch 148027-03");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Vulnerability in the Solaris component of Oracle and Sun Systems
Products Suite (subcomponent: RBAC Configuration). Supported versions
that are affected are 8, 9 and 10. Very difficult to exploit
vulnerability requiring logon to Operating System plus additional,
multiple logins to components. Successful attack of this vulnerability
can escalate attacker privileges resulting in unauthorized Operating
System takeover including arbitrary code execution.

Vulnerability in the Solaris component of Oracle and Sun Systems
Products Suite (subcomponent: Utility/pax). Supported versions that
are affected are 8, 9, 10 and 11. Difficult to exploit vulnerability
requiring logon to Operating System. Successful attack of this
vulnerability can result in unauthorized update, insert or delete
access to some Solaris accessible data and ability to cause a partial
denial of service (partial DOS) of Solaris.

This plugin has been deprecated and either replaced with individual
148027 patch-revision plugins, or deemed non-security related."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/148027-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:M/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}

exit(0, "This plugin has been deprecated. Consult specific patch-revision plugins for patch 148027 instead.");
