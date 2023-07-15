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
  script_id(64655);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-0570", "CVE-2013-0406", "CVE-2013-0408", "CVE-2013-0413", "CVE-2013-3745");
  script_bugtraq_id(61261);

  script_name(english:"Solaris 10 (sparc) : 147147-26 (deprecated)");
  script_summary(english:"Check for patch 147147-26");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Vulnerability in the Solaris component of Oracle and Sun Systems
Products Suite (subcomponent: Libraries/Libc). Supported versions that
are affected are 8, 9, 10 and 11. Easily exploitable vulnerability
requiring logon to Operating System. Successful attack of this
vulnerability can result in unauthorized ability to cause a partial
denial of service (partial DOS) of Solaris.

Vulnerability in the Solaris component of Oracle and Sun Systems
Products Suite (subcomponent: Kernel/IPsec). The supported version
that is affected is 10. Difficult to exploit vulnerability allows
successful unauthenticated network attacks via TCP/IP. Successful
attack of this vulnerability can result in unauthorized update, insert
or delete access to some Solaris accessible data.

Vulnerability in the Solaris component of Oracle and Sun Systems
Products Suite (subcomponent: CPU performance counters drivers). The
supported version that is affected is 10. Easily exploitable
vulnerability requiring logon to Operating System plus additional
login/authentication to component or subcomponent. Successful attack
of this vulnerability can escalate attacker privileges resulting in
unauthorized Operating System hang or frequently repeatable crash
(complete DOS).

Vulnerability in the Solaris component of Oracle and Sun Systems
Products Suite (subcomponent: Remote Execution Service). Supported
versions that are affected are 10 and 11. Difficult to exploit
vulnerability requiring logon to Operating System. Successful attack
of this vulnerability can result in unauthorized update, insert or
delete access to some Solaris accessible data as well as read access
to a subset of Solaris accessible data and ability to cause a partial
denial of service (partial DOS) of Solaris.

Vulnerability in the Solaris component of Oracle and Sun Systems
Products Suite (subcomponent: Libraries/Libc). Supported versions that
are affected are 8, 9, 10 and 11. Easily exploitable vulnerability
requiring logon to Operating System. Successful attack of this
vulnerability can result in unauthorized ability to cause a hang or
frequently repeatable crash (complete DOS) of Solaris.

This plugin has been deprecated and either replaced with individual
147147 patch-revision plugins, or deemed non-security related."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/147147-26"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

exit(0, "This plugin has been deprecated. Consult specific patch-revision plugins for patch 147147 instead.");
