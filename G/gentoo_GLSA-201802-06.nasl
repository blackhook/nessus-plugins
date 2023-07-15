#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201802-06.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(106887);
  script_version("3.3");
  script_cvs_date("Date: 2019/04/05 23:25:06");

  script_cve_id("CVE-2018-6871");
  script_xref(name:"GLSA", value:"201802-06");

  script_name(english:"GLSA-201802-06 : LibreOffice: Information disclosure");
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
"The remote host is affected by the vulnerability described in GLSA-201802-06
(LibreOffice: Information disclosure)

    It was discovered that missing restrictions in the implementation of the
      WEBSERVICE function in LibreOffice could result in the disclosure of
      arbitrary files.
  
Impact :

    A remote attacker could entice a user to open a specially crafted
      document using LibreOffice, possibly resulting in the disclosure of
      arbitrary files readable by the victim.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201802-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All LibreOffice users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-office/libreoffice-5.4.5.1'
    All LibreOffice binary users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-office/libreoffice-bin-5.4.5.1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libreoffice-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"app-office/libreoffice", unaffected:make_list("ge 5.4.5.1"), vulnerable:make_list("lt 5.4.5.1"))) flag++;
if (qpkg_check(package:"app-office/libreoffice-bin", unaffected:make_list("ge 5.4.5.1"), vulnerable:make_list("lt 5.4.5.1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "LibreOffice");
}
