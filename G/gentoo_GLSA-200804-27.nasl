#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200804-27.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(32073);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2008-1227", "CVE-2008-1429", "CVE-2008-1552");
  script_xref(name:"GLSA", value:"200804-27");

  script_name(english:"GLSA-200804-27 : SILC: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200804-27
(SILC: Multiple vulnerabilities)

    Nathan G. Grennan reported a boundary error in SILC Toolkit
    within the silc_fingerprint() function in the file
    lib/silcutil/silcutil.c when passing overly long data, resulting in a
    stack-based buffer overflow (CVE-2008-1227).
    A vulnerability
    has been reported in SILC Server which is caused due to an error in the
    handling of 'NEW_CLIENT' packets that do not contain a nickname
    (CVE-2008-1429).
    Ariel Waissbein, Pedro Varangot, Martin
    Mizrahi, Oren Isacson, Carlos Garcia, and Ivan Arce of Core Security
    Technologies reported that SILC Client, Server, and Toolkit contain a
    vulnerability in the silc_pkcs1_decode() function in the silccrypt
    library (silcpkcs1.c), resulting in an integer underflow, signedness
    error, and a buffer overflow (CVE-2008-1552).
  
Impact :

    A remote attacker could exploit these vulnerabilities to cause a Denial
    of Service or execute arbitrary code with the privileges of the user
    running the application.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200804-27"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All SILC Toolkit users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-im/silc-toolkit-1.1.7'
    All SILC Client users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-im/silc-client-1.1.4'
    All SILC Server users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-im/silc-server-1.1.2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:silc-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:silc-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:silc-toolkit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-im/silc-server", unaffected:make_list("ge 1.1.2"), vulnerable:make_list("lt 1.1.2"))) flag++;
if (qpkg_check(package:"net-im/silc-toolkit", unaffected:make_list("ge 1.1.7"), vulnerable:make_list("lt 1.1.7"))) flag++;
if (qpkg_check(package:"net-im/silc-client", unaffected:make_list("ge 1.1.4"), vulnerable:make_list("lt 1.1.4"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "SILC");
}
