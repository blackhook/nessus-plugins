#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202208-24.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(164108);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/15");

  script_cve_id(
    "CVE-2021-3998",
    "CVE-2021-3999",
    "CVE-2021-35942",
    "CVE-2021-38604",
    "CVE-2022-23218",
    "CVE-2022-23219"
  );

  script_name(english:"GLSA-202208-24 : GNU C Library: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202208-24 (GNU C Library: Multiple Vulnerabilities)

  - The wordexp function in the GNU C Library (aka glibc) through 2.33 may crash or read arbitrary memory in
    parse_param (in posix/wordexp.c) when called with an untrusted, crafted pattern, potentially resulting in
    a denial of service or disclosure of information. This occurs because atoi was used but strtoul should
    have been used to ensure correct calculations. (CVE-2021-35942)

  - In librt in the GNU C Library (aka glibc) through 2.34, sysdeps/unix/sysv/linux/mq_notify.c mishandles
    certain NOTIFY_REMOVED data, leading to a NULL pointer dereference. NOTE: this vulnerability was
    introduced as a side effect of the CVE-2021-33574 fix. (CVE-2021-38604)

  - The deprecated compatibility function svcunix_create in the sunrpc module of the GNU C Library (aka glibc)
    through 2.34 copies its path argument on the stack without validating its length, which may result in a
    buffer overflow, potentially resulting in a denial of service or (if an application is not built with a
    stack protector enabled) arbitrary code execution. (CVE-2022-23218)

  - The deprecated compatibility function clnt_create in the sunrpc module of the GNU C Library (aka glibc)
    through 2.34 copies its hostname argument on the stack without validating its length, which may result in
    a buffer overflow, potentially resulting in a denial of service or (if an application is not built with a
    stack protector enabled) arbitrary code execution. (CVE-2022-23219)

  -  Please review the referenced CVE identifiers for details.  (CVE-2021-3998)

  - glibc: Off-by-one buffer overflow/underflow in getcwd() (CVE-2021-3999)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202208-24");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=803437");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=807935");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=831096");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=831212");
  script_set_attribute(attribute:"solution", value:
"All GNU C Library users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=sys-libs/glibc-2.34-r7");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23219");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : "sys-libs/glibc",
    'unaffected' : make_list("ge 2.34"),
    'vulnerable' : make_list("lt 2.34")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GNU C Library");
}
