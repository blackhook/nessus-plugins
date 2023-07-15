
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
  script_id(71659);
  script_version("1.22");
  script_cvs_date("Date: 2018/07/30 13:40:15");

  script_cve_id("CVE-2013-3746", "CVE-2015-2616");

  script_name(english:"Solaris 10 (sparc) : 145333-39 (deprecated)");
  script_summary(english:"Check for patch 145333-39");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Vulnerability in the Solaris Cluster component of Oracle and Sun
Systems Products Suite (subcomponent: Zone Cluster Infrastructure).
Supported versions that are affected are 3.2, 3.3 and 4 prior to 4.1
SRU 3. Easily exploitable vulnerability requiring logon to Operating
System. Successful attack of this vulnerability can result in
unauthorized Operating System takeover including arbitrary code
execution.

This plugin has been deprecated and either replaced with individual
145333 patch-revision plugins, or deemed non-security related."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/145333-39"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}

exit(0, "This plugin has been deprecated. Consult specific patch-revision plugins for patch 145333 instead.");
