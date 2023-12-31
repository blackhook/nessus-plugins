#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200410-03.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15424);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2001-0554");
  script_xref(name:"GLSA", value:"200410-03");

  script_name(english:"GLSA-200410-03 : NetKit-telnetd: buffer overflows in telnet and telnetd");
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
"The remote host is affected by the vulnerability described in GLSA-200410-03
(NetKit-telnetd: buffer overflows in telnet and telnetd)

    A possible buffer overflow exists in the parsing of option strings by the
    telnet daemon, where proper bounds checking is not applied when writing to
    a buffer. Additionaly, another possible buffer overflow has been found by
    Josh Martin in the handling of the environment variable HOME.
  
Impact :

    A remote attacker sending a specially crafted options string to the telnet
    daemon could be able to run arbitrary code with the privileges of the user
    running the telnet daemon, usually root. Furthermore, an attacker could
    make use of an overlong HOME variable to cause a buffer overflow in the
    telnet client, potentially leading to the local execution of arbitrary
    code.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=264846
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=264846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200410-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All NetKit-telnetd users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=net-misc/netkit-telnetd-0.17-r4'
    # emerge '>=net-misc/netkit-telnetd-0.17-r4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:netkit-telnetd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/06");
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

if (qpkg_check(package:"net-misc/netkit-telnetd", unaffected:make_list("ge 0.17-r4"), vulnerable:make_list("le 0.17-r3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NetKit-telnetd");
}
