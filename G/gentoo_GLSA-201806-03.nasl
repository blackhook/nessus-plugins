#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201806-03.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(110524);
  script_version("1.4");
  script_cvs_date("Date: 2018/09/04 13:20:07");

  script_cve_id("CVE-2017-18284", "CVE-2017-18285");
  script_xref(name:"GLSA", value:"201806-03");

  script_name(english:"GLSA-201806-03 : BURP: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201806-03
(BURP: Multiple vulnerabilities)

    It was discovered that Gentoo&rsquo;s BURP ebuild does not properly set
      permissions or place the pid file in a safe directory.
  
Impact :

    A local attacker could escalate privileges.
  
Workaround :

    Users should ensure the proper permissions are set as discussed in the
      referenced bugs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201806-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All BURP users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-backup/burp-2.1.32'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:burp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"app-backup/burp", unaffected:make_list("ge 2.1.32"), vulnerable:make_list("lt 2.1.32"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:qpkg_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "BURP");
}
