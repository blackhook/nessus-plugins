#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2182-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135939);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2020-11008");

  script_name(english:"Debian DLA-2182-1 : git security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Carlo Arenas discovered a flaw in git, a fast, scalable, distributed
revision control system. With a crafted URL that contains a newline or
empty host, or lacks a scheme, the credential helper machinery can be
fooled into providing credential information that is not appropriate
for the protocol in use and host being contacted.

For Debian 8 'Jessie', this problem has been fixed in version
1:2.1.4-2.1+deb8u10.

We recommend that you upgrade your git packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/04/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/git"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11008");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-arch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-daemon-run");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-daemon-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-mediawiki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gitweb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/24");
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
if (deb_check(release:"8.0", prefix:"git", reference:"1:2.1.4-2.1+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"git-all", reference:"1:2.1.4-2.1+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"git-arch", reference:"1:2.1.4-2.1+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"git-core", reference:"1:2.1.4-2.1+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"git-cvs", reference:"1:2.1.4-2.1+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"git-daemon-run", reference:"1:2.1.4-2.1+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"git-daemon-sysvinit", reference:"1:2.1.4-2.1+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"git-doc", reference:"1:2.1.4-2.1+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"git-el", reference:"1:2.1.4-2.1+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"git-email", reference:"1:2.1.4-2.1+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"git-gui", reference:"1:2.1.4-2.1+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"git-man", reference:"1:2.1.4-2.1+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"git-mediawiki", reference:"1:2.1.4-2.1+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"git-svn", reference:"1:2.1.4-2.1+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"gitk", reference:"1:2.1.4-2.1+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"gitweb", reference:"1:2.1.4-2.1+deb8u10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
