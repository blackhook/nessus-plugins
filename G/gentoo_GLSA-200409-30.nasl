#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200409-30.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14798);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2004-1379", "CVE-2004-1475", "CVE-2004-1476");
  script_xref(name:"GLSA", value:"200409-30");

  script_name(english:"GLSA-200409-30 : xine-lib: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200409-30
(xine-lib: Multiple vulnerabilities)

    xine-lib contains two stack-based overflows and one heap-based
    overflow. In the code reading VCD disc labels, the ISO disc label is
    copied into an unprotected stack buffer of fixed size. Also, there is a
    buffer overflow in the code that parses subtitles and prepares them for
    display (XSA-2004-4). Finally, xine-lib contains a heap-based overflow
    in the DVD sub-picture decoder (XSA-2004-5).
    (Please note that the VCD MRL issue mentioned in XSA-2004-4 was fixed
    with GLSA 200408-18.)
  
Impact :

    With carefully-crafted VCDs, DVDs, MPEGs or subtitles, an attacker may
    cause xine-lib to execute arbitrary code with the permissions of the
    user.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://www.securityfocus.com/archive/1/375485/2004-09-02/2004-09-08/0
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.securityfocus.com/archive/1/375485/2004-09-02/2004-09-08/0"
  );
  # http://www.securityfocus.com/archive/1/375482/2004-09-02/2004-09-08/0
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.securityfocus.com/archive/1/375482/2004-09-02/2004-09-08/0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200409-30"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All xine-lib users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=media-libs/xine-lib-1_rc6'
    # emerge '>=media-libs/xine-lib-1_rc6'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xine-lib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/23");
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

if (qpkg_check(package:"media-libs/xine-lib", unaffected:make_list("ge 1_rc6"), vulnerable:make_list("le 1_rc5-r3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xine-lib");
}
