#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4581. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(131966);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2019-1348", "CVE-2019-1349", "CVE-2019-1352", "CVE-2019-1353", "CVE-2019-1387", "CVE-2019-19604");
  script_xref(name:"DSA", value:"4581");

  script_name(english:"Debian DSA-4581-1 : git - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been discovered in git, a fast, scalable,
distributed revision control system.

  - CVE-2019-1348
    It was reported that the --export-marks option of git
    fast-import is exposed also via the in-stream command
    feature export-marks=..., allowing to overwrite
    arbitrary paths.

  - CVE-2019-1387
    It was discovered that submodule names are not validated
    strictly enough, allowing very targeted attacks via
    remote code execution when performing recursive clones.

  - CVE-2019-19604
    Joern Schneeweisz reported a vulnerability, where a
    recursive clone followed by a submodule update could
    execute code contained within the repository without the
    user explicitly having asked for that. It is now
    disallowed for `.gitmodules` to have entries that set
    `submodule.<name>.update=!command`.

In addition this update addresses a number of security issues which
are only an issue if git is operating on an NTFS filesystem
(CVE-2019-1349, CVE-2019-1352 and CVE-2019-1353 )."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-1348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-1387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-19604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-1349"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-1352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-1353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/git"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/git"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/git"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4581"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the git packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 1:2.11.0-3+deb9u5.

For the stable distribution (buster), these problems have been fixed
in version 1:2.20.1-2+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19604");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"git", reference:"1:2.20.1-2+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"git-all", reference:"1:2.20.1-2+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"git-cvs", reference:"1:2.20.1-2+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"git-daemon-run", reference:"1:2.20.1-2+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"git-daemon-sysvinit", reference:"1:2.20.1-2+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"git-doc", reference:"1:2.20.1-2+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"git-el", reference:"1:2.20.1-2+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"git-email", reference:"1:2.20.1-2+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"git-gui", reference:"1:2.20.1-2+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"git-man", reference:"1:2.20.1-2+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"git-mediawiki", reference:"1:2.20.1-2+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"git-svn", reference:"1:2.20.1-2+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"gitk", reference:"1:2.20.1-2+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"gitweb", reference:"1:2.20.1-2+deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"git", reference:"1:2.11.0-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"git-all", reference:"1:2.11.0-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"git-arch", reference:"1:2.11.0-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"git-core", reference:"1:2.11.0-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"git-cvs", reference:"1:2.11.0-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"git-daemon-run", reference:"1:2.11.0-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"git-daemon-sysvinit", reference:"1:2.11.0-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"git-doc", reference:"1:2.11.0-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"git-el", reference:"1:2.11.0-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"git-email", reference:"1:2.11.0-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"git-gui", reference:"1:2.11.0-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"git-man", reference:"1:2.11.0-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"git-mediawiki", reference:"1:2.11.0-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"git-svn", reference:"1:2.11.0-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"gitk", reference:"1:2.11.0-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"gitweb", reference:"1:2.11.0-3+deb9u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
