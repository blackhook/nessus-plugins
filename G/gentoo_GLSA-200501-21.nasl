#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200501-21.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(16412);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2004-1182");
  script_xref(name:"GLSA", value:"200501-21");

  script_name(english:"GLSA-200501-21 : HylaFAX: hfaxd unauthorized login vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200501-21
(HylaFAX: hfaxd unauthorized login vulnerability)

    The code used by hfaxd to match a given username and hostname with
    an entry in the hosts.hfaxd file is insufficiently protected against
    malicious entries.
  
Impact :

    If the HylaFAX installation uses a weak hosts.hfaxd file, a remote
    attacker could authenticate using a malicious username or hostname and
    bypass the intended access restrictions.
  
Workaround :

    As a workaround, administrators may consider adding passwords to
    all entries in the hosts.hfaxd file."
  );
  # http://marc.theaimsgroup.com/?l=hylafax&m=110545119911558&w=2
  script_set_attribute(
    attribute:"see_also",
    value:"https://marc.info/?l=hylafax&m=110545119911558&w=2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200501-21"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All HylaFAX users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/hylafax-4.2.0-r2'
    Note: Due to heightened security, weak entries in the
    hosts.hfaxd file may no longer work. Please see the HylaFAX
    documentation for details of accepted syntax in the hosts.hfaxd file."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:hylafax");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"net-misc/hylafax", unaffected:make_list("ge 4.2.0-r2"), vulnerable:make_list("lt 4.2.0-r2"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:qpkg_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "HylaFAX");
}
