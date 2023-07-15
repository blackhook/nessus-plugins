#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2285-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(138858);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/27");

  script_cve_id("CVE-2017-11464", "CVE-2019-20446");

  script_name(english:"Debian DLA-2285-1 : librsvg security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been found in librsvg, an SVG rendering
library. This update corrects some denial of service issues via
exponential element processing, stack exhaustion or application crash
when processing specially crafted files, as well as some memory safety
issues.

For Debian 9 stretch, these problems have been fixed in version
2.40.21-0+deb9u1.

We recommend that you upgrade your librsvg packages.

For the detailed security status of librsvg please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/librsvg

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/07/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/librsvg"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/librsvg"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-rsvg-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librsvg2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librsvg2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librsvg2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librsvg2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librsvg2-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/23");
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
if (deb_check(release:"9.0", prefix:"gir1.2-rsvg-2.0", reference:"2.40.21-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"librsvg2-2", reference:"2.40.21-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"librsvg2-bin", reference:"2.40.21-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"librsvg2-common", reference:"2.40.21-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"librsvg2-dev", reference:"2.40.21-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"librsvg2-doc", reference:"2.40.21-0+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
