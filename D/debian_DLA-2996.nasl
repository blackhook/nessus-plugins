#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2996. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(161327);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2017-9527",
    "CVE-2018-10191",
    "CVE-2018-11743",
    "CVE-2018-12249",
    "CVE-2018-14337",
    "CVE-2020-15866"
  );

  script_name(english:"Debian DLA-2996-1 : mruby - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2996 advisory.

  - The mark_context_stack function in gc.c in mruby through 1.2.0 allows attackers to cause a denial of
    service (heap-based use-after-free and application crash) or possibly have unspecified other impact via a
    crafted .rb file. (CVE-2017-9527)

  - In versions of mruby up to and including 1.4.0, an integer overflow exists in src/vm.c::mrb_vm_exec() when
    handling OP_GETUPVAR in the presence of deep scope nesting, resulting in a use-after-free. An attacker
    that can cause Ruby code to be run can use this to possibly execute arbitrary code. (CVE-2018-10191)

  - The init_copy function in kernel.c in mruby 1.4.1 makes initialize_copy calls for TT_ICLASS objects, which
    allows attackers to cause a denial of service (mrb_hash_keys uninitialized pointer and application crash)
    or possibly have unspecified other impact. (CVE-2018-11743)

  - An issue was discovered in mruby 1.4.1. There is a NULL pointer dereference in mrb_class_real because
    class BasicObject is not properly supported in class.c. (CVE-2018-12249)

  - The CHECK macro in mrbgems/mruby-sprintf/src/sprintf.c in mruby 1.4.1 contains a signed integer overflow,
    possibly leading to out-of-bounds memory access because the mrb_str_resize function in string.c does not
    check for a negative length. (CVE-2018-14337)

  - mruby through 2.1.2-rc has a heap-based buffer overflow in the mrb_yield_with_class function in vm.c
    because of incorrect VM stack handling. It can be triggered via the stack_copy function. (CVE-2020-15866)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/mruby");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2996");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-9527");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-10191");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-11743");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-12249");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-14337");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-15866");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/mruby");
  script_set_attribute(attribute:"solution", value:
"Upgrade the mruby packages.

For Debian 9 stretch, these problems have been fixed in version 1.2.0+20161228+git30d5424a-1+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15866");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmruby-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mruby");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'libmruby-dev', 'reference': '1.2.0+20161228+git30d5424a-1+deb9u1'},
    {'release': '9.0', 'prefix': 'mruby', 'reference': '1.2.0+20161228+git30d5424a-1+deb9u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmruby-dev / mruby');
}
