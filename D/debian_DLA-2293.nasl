#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2293-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139244);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/06");

  script_cve_id("CVE-2017-17458", "CVE-2018-1000132", "CVE-2018-13346", "CVE-2018-13347", "CVE-2018-13348", "CVE-2019-3902");

  script_name(english:"Debian DLA-2293-1 : mercurial security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were discovered in mercurial, an easy-to-use,
scalable distributed version control system.

CVE-2017-17458

In Mercurial before 4.4.1, it is possible that a specially malformed
repository can cause Git subrepositories to run arbitrary code in the
form of a .git/hooks/post-update script checked into the repository.
Typical use of Mercurial prevents construction of such repositories,
but they can be created programmatically.

CVE-2018-13346

The mpatch_apply function in mpatch.c in Mercurial before 4.6.1
incorrectly proceeds in cases where the fragment start is past the end
of the original data.

CVE-2018-13347

mpatch.c in Mercurial before 4.6.1 mishandles integer addition and
subtraction.

CVE-2018-13348

The mpatch_decode function in mpatch.c in Mercurial before 4.6.1
mishandles certain situations where there should be at least 12 bytes
remaining after the current position in the patch data, but actually
are not.

CVE-2018-1000132

Mercurial version 4.5 and earlier contains a Incorrect Access Control
(CWE-285) vulnerability in Protocol server that can result in
Unauthorized data access. This attack appear to be exploitable via
network connectivity. This vulnerability appears to have been fixed in
4.5.1.

CVE-2019-3902

Symbolic links and subrepositories could be used defeat Mercurial's
path-checking logic and write files outside the repository root.

For Debian 9 stretch, these problems have been fixed in version
4.0-1+deb9u2.

We recommend that you upgrade your mercurial packages.

For the detailed security status of mercurial please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/mercurial

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/07/msg00032.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/mercurial"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/mercurial"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the affected mercurial, and mercurial-common packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mercurial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mercurial-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/03");
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
if (deb_check(release:"9.0", prefix:"mercurial", reference:"4.0-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"mercurial-common", reference:"4.0-1+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
