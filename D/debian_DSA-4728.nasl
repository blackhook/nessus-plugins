#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4728. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(138648);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/09");

  script_cve_id("CVE-2020-10756", "CVE-2020-13361", "CVE-2020-13362", "CVE-2020-13659", "CVE-2020-13754");
  script_xref(name:"DSA", value:"4728");
  script_xref(name:"IAVB", value:"2020-B-0041-S");

  script_name(english:"Debian DSA-4728-1 : qemu - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple security issues were discovered in QEMU, a fast processor
emulator, which could result in denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=964247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=961887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=961887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=961888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/qemu"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/qemu"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4728"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the qemu packages.

For the stable distribution (buster), these problems have been fixed
in version 1:3.1+dfsg-8+deb10u6."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13754");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"qemu", reference:"1:3.1+dfsg-8+deb10u6")) flag++;
if (deb_check(release:"10.0", prefix:"qemu-block-extra", reference:"1:3.1+dfsg-8+deb10u6")) flag++;
if (deb_check(release:"10.0", prefix:"qemu-guest-agent", reference:"1:3.1+dfsg-8+deb10u6")) flag++;
if (deb_check(release:"10.0", prefix:"qemu-kvm", reference:"1:3.1+dfsg-8+deb10u6")) flag++;
if (deb_check(release:"10.0", prefix:"qemu-system", reference:"1:3.1+dfsg-8+deb10u6")) flag++;
if (deb_check(release:"10.0", prefix:"qemu-system-arm", reference:"1:3.1+dfsg-8+deb10u6")) flag++;
if (deb_check(release:"10.0", prefix:"qemu-system-common", reference:"1:3.1+dfsg-8+deb10u6")) flag++;
if (deb_check(release:"10.0", prefix:"qemu-system-data", reference:"1:3.1+dfsg-8+deb10u6")) flag++;
if (deb_check(release:"10.0", prefix:"qemu-system-gui", reference:"1:3.1+dfsg-8+deb10u6")) flag++;
if (deb_check(release:"10.0", prefix:"qemu-system-mips", reference:"1:3.1+dfsg-8+deb10u6")) flag++;
if (deb_check(release:"10.0", prefix:"qemu-system-misc", reference:"1:3.1+dfsg-8+deb10u6")) flag++;
if (deb_check(release:"10.0", prefix:"qemu-system-ppc", reference:"1:3.1+dfsg-8+deb10u6")) flag++;
if (deb_check(release:"10.0", prefix:"qemu-system-sparc", reference:"1:3.1+dfsg-8+deb10u6")) flag++;
if (deb_check(release:"10.0", prefix:"qemu-system-x86", reference:"1:3.1+dfsg-8+deb10u6")) flag++;
if (deb_check(release:"10.0", prefix:"qemu-user", reference:"1:3.1+dfsg-8+deb10u6")) flag++;
if (deb_check(release:"10.0", prefix:"qemu-user-binfmt", reference:"1:3.1+dfsg-8+deb10u6")) flag++;
if (deb_check(release:"10.0", prefix:"qemu-user-static", reference:"1:3.1+dfsg-8+deb10u6")) flag++;
if (deb_check(release:"10.0", prefix:"qemu-utils", reference:"1:3.1+dfsg-8+deb10u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
