#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2447-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(142832);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/18");

  script_name(english:"Debian DLA-2447-2 : pacemaker regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The update of pacemaker released as DLA-2447-1 caused a regression
when the communication between the Corosync cluster engine and
pacemaker takes place. A permission problem prevents IPC requests
between cluster nodes. The patch for CVE-2020-25654 has been reverted
until a better solution can be found.

For Debian 9 stretch, this problem has been fixed in version
1.1.16-1+deb9u2.

We recommend that you upgrade your pacemaker packages.

For the detailed security status of pacemaker please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/pacemaker

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/11/msg00029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/pacemaker"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/pacemaker"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcib4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcrmcluster-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcrmcluster4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcrmcommon-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcrmcommon3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcrmservice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcrmservice3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblrmd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblrmd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpe-rules2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpe-status10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpengine-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpengine10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libstonithd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libstonithd2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtransitioner2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pacemaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pacemaker-cli-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pacemaker-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pacemaker-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pacemaker-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pacemaker-resource-agents");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/12");
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
if (deb_check(release:"9.0", prefix:"libcib-dev", reference:"1.1.16-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcib4", reference:"1.1.16-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcrmcluster-dev", reference:"1.1.16-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcrmcluster4", reference:"1.1.16-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcrmcommon-dev", reference:"1.1.16-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcrmcommon3", reference:"1.1.16-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcrmservice-dev", reference:"1.1.16-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcrmservice3", reference:"1.1.16-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"liblrmd-dev", reference:"1.1.16-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"liblrmd1", reference:"1.1.16-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libpe-rules2", reference:"1.1.16-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libpe-status10", reference:"1.1.16-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libpengine-dev", reference:"1.1.16-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libpengine10", reference:"1.1.16-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libstonithd-dev", reference:"1.1.16-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libstonithd2", reference:"1.1.16-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libtransitioner2", reference:"1.1.16-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"pacemaker", reference:"1.1.16-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"pacemaker-cli-utils", reference:"1.1.16-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"pacemaker-common", reference:"1.1.16-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"pacemaker-doc", reference:"1.1.16-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"pacemaker-remote", reference:"1.1.16-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"pacemaker-resource-agents", reference:"1.1.16-1+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
