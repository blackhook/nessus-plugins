#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202210-31.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(166712);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/31");

  script_cve_id(
    "CVE-2021-3598",
    "CVE-2021-3605",
    "CVE-2021-3933",
    "CVE-2021-3941",
    "CVE-2021-20304",
    "CVE-2021-23169",
    "CVE-2021-45942"
  );

  script_name(english:"GLSA-202210-31 : OpenEXR: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202210-31 (OpenEXR: Multiple Vulnerabilities)

  - A flaw was found in OpenEXR's hufDecode functionality. This flaw allows an attacker who can pass a crafted
    file to be processed by OpenEXR, to trigger an undefined right shift error. The highest threat from this
    vulnerability is to system availability. (CVE-2021-20304)

  - A heap-buffer overflow was found in the copyIntoFrameBuffer function of OpenEXR in versions before 3.0.1.
    An attacker could use this flaw to execute arbitrary code with the permissions of the user running the
    application compiled against OpenEXR. (CVE-2021-23169)

  - There's a flaw in OpenEXR's ImfDeepScanLineInputFile functionality in versions prior to 3.0.5. An attacker
    who is able to submit a crafted file to an application linked with OpenEXR could cause an out-of-bounds
    read. The greatest risk from this flaw is to application availability. (CVE-2021-3598)

  - There's a flaw in OpenEXR's rleUncompress functionality in versions prior to 3.0.5. An attacker who is
    able to submit a crafted file to an application linked with OpenEXR could cause an out-of-bounds read. The
    greatest risk from this flaw is to application availability. (CVE-2021-3605)

  - An integer overflow could occur when OpenEXR processes a crafted file on systems where size_t < 64 bits.
    This could cause an invalid bytesPerLine and maxBytesPerLine value, which could lead to problems with
    application stability or lead to other attack paths. (CVE-2021-3933)

  - In ImfChromaticities.cpp routine RGBtoXYZ(), there are some division operations such as `float Z = (1 -
    chroma.white.x - chroma.white.y) * Y / chroma.white.y;` and `chroma.green.y * (X + Z))) / d;` but the
    divisor is not checked for a 0 value. A specially crafted file could trigger a divide-by-zero condition
    which could affect the availability of programs linked with OpenEXR. (CVE-2021-3941)

  - OpenEXR 3.1.x before 3.1.4 has a heap-based buffer overflow in Imf_3_1::LineCompositeTask::execute (called
    from IlmThread_3_1::NullThreadPoolProvider::addTask and IlmThread_3_1::ThreadPool::addGlobalTask). NOTE:
    db217f2 may be inapplicable. (CVE-2021-45942)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202210-31");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=787452");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=801373");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=810541");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=817431");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=830384");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=838079");
  script_set_attribute(attribute:"solution", value:
"All OpenEXR users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=media-libs/openexr-3.1.5");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23169");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openexr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'media-libs/openexr',
    'unaffected' : make_list("ge 3.1.5", "lt 3.0.0"),
    'vulnerable' : make_list("lt 3.1.5")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}

# This plugin has a different number of unaffected and vulnerable versions for
# one or more packages. To ensure proper detection, a separate line should be 
# used for each fixed/vulnerable version pair.

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'OpenEXR');
}
