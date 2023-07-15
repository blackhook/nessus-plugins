#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1448-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111389);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-1116");

  script_name(english:"Debian DLA-1448-1 : policykit-1 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that there was a denial of service vulnerability in
policykit-1, a framework for managing administrative policies and
privileges.

For Debian 8 'Jessie', this issue has been fixed in policykit-1
version 0.105-15~deb8u3.

We recommend that you upgrade your policykit-1 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/07/msg00042.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/policykit-1"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-polkit-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpolkit-agent-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpolkit-agent-1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpolkit-backend-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpolkit-backend-1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpolkit-gobject-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpolkit-gobject-1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:policykit-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:policykit-1-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"gir1.2-polkit-1.0", reference:"0.105-15~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libpolkit-agent-1-0", reference:"0.105-15~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libpolkit-agent-1-dev", reference:"0.105-15~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libpolkit-backend-1-0", reference:"0.105-15~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libpolkit-backend-1-dev", reference:"0.105-15~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libpolkit-gobject-1-0", reference:"0.105-15~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libpolkit-gobject-1-dev", reference:"0.105-15~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"policykit-1", reference:"0.105-15~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"policykit-1-doc", reference:"0.105-15~deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
