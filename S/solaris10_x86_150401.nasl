
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
  script_id(68873);
  script_version("1.112");
  script_cvs_date("Date: 2018/07/30 15:31:32");

  script_cve_id("CVE-2013-3799", "CVE-2013-5862", "CVE-2014-0447", "CVE-2014-4215", "CVE-2018-2710", "CVE-2018-2717");
  script_bugtraq_id(61273, 63072, 66826, 68569);

  script_name(english:"Solaris 10 (x86) : 150401-59 (deprecated)");
  script_summary(english:"Check for patch 150401-59");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Vulnerability in the Solaris component of Oracle Sun Systems Products
Suite (subcomponent: Kernel). The supported version that is affected
is 10. Easily exploitable vulnerability allows unauthenticated
attacker with network access via ICMP to compromise Solaris.
Successful attacks of this vulnerability can result in unauthorized
ability to cause a hang or frequently repeatable crash (complete DOS)
of Solaris.

Vulnerability in the Solaris component of Oracle Sun Systems Products
Suite (subcomponent: SPARC Platform). Supported versions that are
affected are 10 and 11.3. Easily exploitable vulnerability allows low
privileged attacker with logon to the infrastructure where Solaris
executes to compromise Solaris. Successful attacks require human
interaction from a person other than the attacker. Successful attacks
of this vulnerability can result in unauthorized creation, deletion or
modification access to critical data or all Solaris accessible data as
well as unauthorized access to critical data or complete access to all
Solaris accessible data.

This plugin has been deprecated and either replaced with individual
150401 patch-revision plugins, or deemed non-security related."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/150401-59"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}

exit(0, "This plugin has been deprecated. Consult specific patch-revision plugins for patch 150401 instead.");
