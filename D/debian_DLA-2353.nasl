#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2353-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(140052);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/02");

  script_cve_id("CVE-2020-11061");

  script_name(english:"Debian DLA-2353-1 : bacula security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An issue has been found in bacula, a network backup service. By
sending oversized digest strings a malicious client can cause a heap
overflow in the director's memory which results in a denial of
service.

For Debian 9 stretch, this problem has been fixed in version
7.4.4+dfsg-6+deb9u2.

We recommend that you upgrade your bacula packages.

For the detailed security status of bacula please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/bacula

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00051.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/bacula"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/bacula"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bacula");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bacula-bscan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bacula-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bacula-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bacula-common-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bacula-common-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bacula-common-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bacula-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bacula-console-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bacula-director");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bacula-director-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bacula-director-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bacula-director-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bacula-fd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bacula-sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bacula-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/31");
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
if (deb_check(release:"9.0", prefix:"bacula", reference:"7.4.4+dfsg-6+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"bacula-bscan", reference:"7.4.4+dfsg-6+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"bacula-client", reference:"7.4.4+dfsg-6+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"bacula-common", reference:"7.4.4+dfsg-6+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"bacula-common-mysql", reference:"7.4.4+dfsg-6+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"bacula-common-pgsql", reference:"7.4.4+dfsg-6+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"bacula-common-sqlite3", reference:"7.4.4+dfsg-6+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"bacula-console", reference:"7.4.4+dfsg-6+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"bacula-console-qt", reference:"7.4.4+dfsg-6+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"bacula-director", reference:"7.4.4+dfsg-6+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"bacula-director-mysql", reference:"7.4.4+dfsg-6+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"bacula-director-pgsql", reference:"7.4.4+dfsg-6+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"bacula-director-sqlite3", reference:"7.4.4+dfsg-6+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"bacula-fd", reference:"7.4.4+dfsg-6+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"bacula-sd", reference:"7.4.4+dfsg-6+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"bacula-server", reference:"7.4.4+dfsg-6+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
