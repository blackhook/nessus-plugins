#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2317-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139428);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/12");

  script_cve_id("CVE-2020-10177");

  script_name(english:"Debian DLA-2317-1 : pillow security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It was noticed that in Pillow before 7.1.0, there are multiple
out-of-bounds reads in libImaging/FliDecode.c.

For Debian 9 stretch, this problem has been fixed in version
4.0.0-4+deb9u2.

We recommend that you upgrade your pillow packages.

For the detailed security status of pillow please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/pillow

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/pillow"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/pillow"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-imaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pil-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pil-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pil.imagetk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pil.imagetk-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-pil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-pil-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-pil.imagetk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-pil.imagetk-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (deb_check(release:"9.0", prefix:"python-imaging", reference:"4.0.0-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"python-pil", reference:"4.0.0-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"python-pil-dbg", reference:"4.0.0-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"python-pil-doc", reference:"4.0.0-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"python-pil.imagetk", reference:"4.0.0-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"python-pil.imagetk-dbg", reference:"4.0.0-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"python3-pil", reference:"4.0.0-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"python3-pil-dbg", reference:"4.0.0-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"python3-pil.imagetk", reference:"4.0.0-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"python3-pil.imagetk-dbg", reference:"4.0.0-4+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
