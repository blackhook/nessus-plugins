#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2666-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149889);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/14");

  script_cve_id("CVE-2021-31535");

  script_name(english:"Debian DLA-2666-1 : libx11 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Roman Fiedler found that libX11, the X11 protocol client library, was
vulnerable to protocol command injection due to insufficient
validation of arguments to some functions.

For Debian 9 stretch, this problem has been fixed in version
2:1.6.4-3+deb9u4.

We recommend that you upgrade your libx11 packages.

For the detailed security status of libx11 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/libx11

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/05/msg00021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libx11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/libx11"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31535");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libx11-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libx11-6-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libx11-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libx11-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libx11-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libx11-xcb-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libx11-xcb1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/25");
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
if (deb_check(release:"9.0", prefix:"libx11-6", reference:"2:1.6.4-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libx11-6-udeb", reference:"2:1.6.4-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libx11-data", reference:"2:1.6.4-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libx11-dev", reference:"2:1.6.4-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libx11-doc", reference:"2:1.6.4-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libx11-xcb-dev", reference:"2:1.6.4-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libx11-xcb1", reference:"2:1.6.4-3+deb9u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
