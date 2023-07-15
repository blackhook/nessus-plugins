#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2692-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(151044);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/17");

  script_cve_id("CVE-2020-26558", "CVE-2021-0129");

  script_name(english:"Debian DLA-2692-1 : bluez security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Two issues have been found in bluez, a package with Bluetooth tools
and daemons. One issue is about a man-in-the-middle attack during
secure pairing, the other is about information disclosure due to
improper access control.

In order to completely fix both issues, you need an updated kernel as
well! For Debian 9 Stretch this has been uploaded some days ago.

For Debian 9 stretch, these problems have been fixed in version
5.43-2+deb9u4.

We recommend that you upgrade your bluez packages.

For the detailed security status of bluez please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/bluez

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/06/msg00022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/bluez"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/bluez"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26558");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez-cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez-hcidump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez-obexd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez-test-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez-test-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbluetooth-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbluetooth3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbluetooth3-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"bluetooth", reference:"5.43-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"bluez", reference:"5.43-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"bluez-cups", reference:"5.43-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"bluez-dbg", reference:"5.43-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"bluez-hcidump", reference:"5.43-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"bluez-obexd", reference:"5.43-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"bluez-test-scripts", reference:"5.43-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"bluez-test-tools", reference:"5.43-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libbluetooth-dev", reference:"5.43-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libbluetooth3", reference:"5.43-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libbluetooth3-dbg", reference:"5.43-2+deb9u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
