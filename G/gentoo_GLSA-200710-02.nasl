#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200710-02.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(26942);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2007-1883", "CVE-2007-1887", "CVE-2007-1900", "CVE-2007-2756", "CVE-2007-2872", "CVE-2007-3007", "CVE-2007-3378", "CVE-2007-3806", "CVE-2007-3996", "CVE-2007-3997", "CVE-2007-3998", "CVE-2007-4652", "CVE-2007-4657", "CVE-2007-4658", "CVE-2007-4659", "CVE-2007-4660", "CVE-2007-4661", "CVE-2007-4662", "CVE-2007-4663", "CVE-2007-4670", "CVE-2007-4727", "CVE-2007-4782", "CVE-2007-4783", "CVE-2007-4784", "CVE-2007-4825", "CVE-2007-4840", "CVE-2007-4887");
  script_xref(name:"GLSA", value:"200710-02");

  script_name(english:"GLSA-200710-02 : PHP: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200710-02
(PHP: Multiple vulnerabilities)

    Several vulnerabilities were found in PHP. Mattias Bengtsson and Philip
    Olausson reported integer overflows in the gdImageCreate() and
    gdImageCreateTrueColor() functions of the GD library which can cause
    heap-based buffer overflows (CVE-2007-3996). Gerhard Wagner discovered
    an integer overflow in the chunk_split() function that can lead to a
    heap-based buffer overflow (CVE-2007-2872). Its incomplete fix caused
    incorrect buffer size calculation due to precision loss, also resulting
    in a possible heap-based buffer overflow (CVE-2007-4661 and
    CVE-2007-4660). A buffer overflow in the sqlite_decode_binary() of the
    SQLite extension found by Stefan Esser that was addressed in PHP 5.2.1
    was not fixed correctly (CVE-2007-1887).
    Stefan Esser discovered an error in the zend_alter_ini_entry() function
    handling a memory_limit violation (CVE-2007-4659). Stefan Esser also
    discovered a flaw when handling interruptions with userspace error
    handlers that can be exploited to read arbitrary heap memory
    (CVE-2007-1883). Disclosure of sensitive memory can also be triggered
    due to insufficient boundary checks in the strspn() and strcspn()
    functions, an issue discovered by Mattias Bengtsson and Philip Olausson
    (CVE-2007-4657)
    Stefan Esser reported incorrect validation in the FILTER_VALIDATE_EMAIL
    filter of the Filter extension allowing arbitrary email header
    injection (CVE-2007-1900). NOTE: This CVE was referenced, but not fixed
    in GLSA 200705-19.
    Stanislav Malyshev found an error with unknown impact in the
    money_format() function when processing '%i' and '%n' tokens
    (CVE-2007-4658). zatanzlatan reported a buffer overflow in the
    php_openssl_make_REQ() function with unknown impact when providing a
    manipulated SSL configuration file (CVE-2007-4662). Possible memory
    corruption when trying to read EXIF data in exif_read_data() and
    exif_thumbnail() occurred with unknown impact.
    Several vulnerabilities that allow bypassing of open_basedir and other
    restrictions were reported, including the glob() function
    (CVE-2007-4663), the session_save_path(), ini_set(), and error_log()
    functions which can allow local command execution (CVE-2007-3378),
    involving the readfile() function (CVE-2007-3007), via the Session
    extension (CVE-2007-4652), via the MySQL extension (CVE-2007-3997) and
    in the dl() function which allows loading extensions outside of the
    specified directory (CVE-2007-4825).
    Multiple Denial of Service vulnerabilities were discovered, including a
    long 'library' parameter in the dl() function (CVE-2007-4887), in
    several iconv and xmlrpc functions (CVE-2007-4840 and CVE-2007-4783),
    in the setlocale() function (CVE-2007-4784), in the glob() and
    fnmatch() function (CVE-2007-4782 and CVE-2007-3806), a floating point
    exception in the wordwrap() function (CVE-2007-3998), a stack
    exhaustion via deeply nested arrays (CVE-2007-4670), an infinite loop
    caused by a specially crafted PNG image in the png_read_info() function
    of libpng (CVE-2007-2756) and several issues related to array
    conversion.
  
Impact :

    Remote attackers might be able to exploit these issues in PHP
    applications making use of the affected functions, potentially
    resulting in the execution of arbitrary code, Denial of Service,
    execution of scripted contents in the context of the affected site,
    security bypass or information leak.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200705-19"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200710-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PHP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-lang/php-5.2.4_p20070914-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 22, 94, 119, 189, 264, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"dev-lang/php", unaffected:make_list("ge 5.2.4_p20070914-r2"), vulnerable:make_list("lt 5.2.4_p20070914-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PHP");
}
