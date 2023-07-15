#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4112. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106820);
  script_version("3.3");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2017-17563", "CVE-2017-17564", "CVE-2017-17565", "CVE-2017-17566");
  script_xref(name:"DSA", value:"4112");

  script_name(english:"Debian DSA-4112-1 : xen - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in the Xen hypervisor :

  - CVE-2017-17563
    Jan Beulich discovered that an incorrect reference count
    overflow check in x86 shadow mode may result in denial
    of service or privilege escalation.

  - CVE-2017-17564
    Jan Beulich discovered that improper x86 shadow mode
    reference count error handling may result in denial of
    service or privilege escalation.

  - CVE-2017-17565
    Jan Beulich discovered that an incomplete bug check in
    x86 log-dirty handling may result in denial of service.

  - CVE-2017-17566
    Jan Beulich discovered that x86 PV guests may gain
    access to internally used pages which could result in
    denial of service or potential privilege escalation.

In addition this update ships the 'Comet' shim to address the Meltdown
class of vulnerabilities for guests with legacy PV kernels. In
addition, the package provides the 'Xen PTI stage 1' mitigation which
is built-in and enabled by default on Intel systems, but can be
disabled with `xpti=false' on the hypervisor command line (It does not
make sense to use both xpti and the Comet shim.)

Please refer to the following URL for more details on how to configure
individual mitigation strategies:
https://xenbits.xen.org/xsa/advisory-254.html

Additional information can also be found in README.pti and
README.comet."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-17563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-17564"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-17565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-17566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://xenbits.xen.org/xsa/advisory-254.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4112"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xen packages.

For the stable distribution (stretch), these problems have been fixed
in version 4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"9.0", prefix:"libxen-4.8", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1")) flag++;
if (deb_check(release:"9.0", prefix:"libxen-dev", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1")) flag++;
if (deb_check(release:"9.0", prefix:"libxenstore3.0", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-amd64", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-arm64", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-armhf", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-amd64", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-arm64", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-armhf", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1")) flag++;
if (deb_check(release:"9.0", prefix:"xen-utils-4.8", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1")) flag++;
if (deb_check(release:"9.0", prefix:"xen-utils-common", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1")) flag++;
if (deb_check(release:"9.0", prefix:"xenstore-utils", reference:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
