#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201904-11.
#
# The advisory text is Copyright (C) 2001-2019 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(123983);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/12 17:35:39");

  script_xref(name:"GLSA", value:"201904-11");

  script_name(english:"GLSA-201904-11 : Portage: Man-in-the-middle");
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
"The remote host is affected by the vulnerability described in GLSA-201904-11
(Portage: Man-in-the-middle)

    A vulnerability was discovered in emerge-delta-webrsync and Portage that
      did not properly validate the revocation status of GPG keys.
  
Impact :

    A remote attacker could conduct a man-in-the-middle attack.  Please
      review the referenced bug for specific details.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201904-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All emerge-delta-webrsync users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-portage/emerge-delta-webrsync-3.7.4'
    All Portage users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=sys-apps/portage-2.3.22'"
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:emerge-delta-webrsync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:portage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"app-portage/emerge-delta-webrsync", unaffected:make_list("ge 3.7.4"), vulnerable:make_list("lt 3.7.4"))) flag++;
if (qpkg_check(package:"sys-apps/portage", unaffected:make_list("ge 2.3.22"), vulnerable:make_list("lt 2.3.22"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Portage");
}
