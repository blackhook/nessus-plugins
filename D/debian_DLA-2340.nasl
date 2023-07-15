#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2340-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139760);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/20");

  script_cve_id("CVE-2019-20218");

  script_name(english:"Debian DLA-2340-2 : sqlite3 regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The update of sqlite3 released as DLA-2340-1 contained an incomplete
fix for CVE-2019-20218. Updated sqlite3 packages are now available to
correct this issue.

For Debian 9 stretch, this problem has been fixed in version
3.16.2-5+deb9u3.

We recommend that you upgrade your sqlite3 packages.

For the detailed security status of sqlite3 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/sqlite3

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/12/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/sqlite3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/sqlite3"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20218");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsqlite3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsqlite3-0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsqlite3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsqlite3-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sqlite3-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"lemon", reference:"3.16.2-5+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libsqlite3-0", reference:"3.16.2-5+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libsqlite3-0-dbg", reference:"3.16.2-5+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libsqlite3-dev", reference:"3.16.2-5+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libsqlite3-tcl", reference:"3.16.2-5+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"sqlite3", reference:"3.16.2-5+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"sqlite3-doc", reference:"3.16.2-5+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
