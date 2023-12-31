#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200405-18.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14504);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2003-0281");
  script_xref(name:"GLSA", value:"200405-18");

  script_name(english:"GLSA-200405-18 : Buffer Overflow in Firebird");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is affected by the vulnerability described in GLSA-200405-18
(Buffer Overflow in Firebird)

    A buffer overflow exists in three Firebird binaries (gds_inet_server,
    gds_lock_mgr, and gds_drop) that is exploitable by setting a large
    value to the INTERBASE environment variable.
  
Impact :

    An attacker could control program execution, allowing privilege
    escalation to the UID of Firebird, full access to Firebird databases,
    and trojaning the Firebird binaries. An attacker could use this to
    compromise other user or root accounts.
  
Workaround :

    There is no known workaround."
  );
  # http://securityfocus.com/bid/7546/info/
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.securityfocus.com/bid/7546/info/"
  );
  # http://sourceforge.net/tracker/?group_id=9028&atid=109028&func=detail&aid=739480
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d6e5192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200405-18"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users should upgrade to the latest version of Firebird:
    # emerge sync
    # emerge -pv '>=dev-db/firebird-1.5'
    # emerge '>=dev-db/firebird-1.5'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firebird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"dev-db/firebird", unaffected:make_list("ge 1.5"), vulnerable:make_list("lt 1.5"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dev-db/firebird");
}
