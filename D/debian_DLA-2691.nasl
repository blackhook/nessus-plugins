#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2691-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(151006);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/05");

  script_cve_id("CVE-2021-33560");

  script_name(english:"Debian DLA-2691-1 : libgcrypt20 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An issue has been found in libgcrypt20, a crypto library. Mishandling
of ElGamal encryption results in a possible side-channel attack and an
interoperability problem with keys not generated by GnuPG/libgcrypt.

For Debian 9 stretch, this problem has been fixed in version
1.7.6-2+deb9u4.

We recommend that you upgrade your libgcrypt20 packages.

For the detailed security status of libgcrypt20 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/libgcrypt20

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/06/msg00021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libgcrypt20"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/libgcrypt20"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33560");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgcrypt-mingw-w64-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgcrypt11-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgcrypt20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgcrypt20-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgcrypt20-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgcrypt20-udeb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/25");
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
if (deb_check(release:"9.0", prefix:"libgcrypt-mingw-w64-dev", reference:"1.7.6-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libgcrypt11-dev", reference:"1.7.6-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libgcrypt20", reference:"1.7.6-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libgcrypt20-dev", reference:"1.7.6-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libgcrypt20-doc", reference:"1.7.6-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libgcrypt20-udeb", reference:"1.7.6-2+deb9u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
