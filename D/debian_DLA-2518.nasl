#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2518-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(144762);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-35492");

  script_name(english:"Debian DLA-2518-1 : cairo security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"LibreOffice slideshow aborts with stack smashing in cairo&rsquo;s
composite_boxes.

For Debian 9 stretch, this problem has been fixed in version
1.14.8-1+deb9u1.

We recommend that you upgrade your cairo packages.

For the detailed security status of cairo please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/cairo

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/01/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/cairo"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/cairo"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-35492");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cairo-perf-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcairo-gobject2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcairo-script-interpreter2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcairo2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcairo2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcairo2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcairo2-udeb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"cairo-perf-utils", reference:"1.14.8-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcairo-gobject2", reference:"1.14.8-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcairo-script-interpreter2", reference:"1.14.8-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcairo2", reference:"1.14.8-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcairo2-dev", reference:"1.14.8-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcairo2-doc", reference:"1.14.8-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcairo2-udeb", reference:"1.14.8-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
