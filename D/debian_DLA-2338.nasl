#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2338-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139758);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/26");

  script_name(english:"Debian DLA-2338-2 : proftpd-dfsg regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The update of proftpd-dfsg released as DLA-2338-1 incorrectly
destroyed the memory pool in function sftp_kex_handle in
contrib/mod_sftp/kex.c which may cause a segmentation fault and thus
prevent sftp connections.

For Debian 9 stretch, this problem has been fixed in version
1.3.5e+r1.3.5b-4+deb9u2.

We recommend that you upgrade your proftpd-dfsg packages.

For the detailed security status of proftpd-dfsg please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/proftpd-dfsg

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00042.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/proftpd-dfsg"
  );
  # https://security-tracker.debian.org/tracker/source-package/proftpd-dfsg
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a98522a3"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-basic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-mod-geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-mod-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-mod-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-mod-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-mod-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-mod-sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/24");
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
if (deb_check(release:"9.0", prefix:"proftpd-basic", reference:"1.3.5e+r1.3.5b-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"proftpd-dev", reference:"1.3.5e+r1.3.5b-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"proftpd-doc", reference:"1.3.5e+r1.3.5b-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"proftpd-mod-geoip", reference:"1.3.5e+r1.3.5b-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"proftpd-mod-ldap", reference:"1.3.5e+r1.3.5b-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"proftpd-mod-mysql", reference:"1.3.5e+r1.3.5b-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"proftpd-mod-odbc", reference:"1.3.5e+r1.3.5b-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"proftpd-mod-pgsql", reference:"1.3.5e+r1.3.5b-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"proftpd-mod-sqlite", reference:"1.3.5e+r1.3.5b-4+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
