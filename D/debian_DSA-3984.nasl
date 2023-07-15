#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3984. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103473);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-14867");
  script_xref(name:"DSA", value:"3984");

  script_name(english:"Debian DSA-3984-1 : git - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"joernchen discovered that the git-cvsserver subcommand of Git, a
distributed version control system, suffers from a shell command
injection vulnerability due to unsafe use of the Perl backtick
operator. The git-cvsserver subcommand is reachable from the git-shell
subcommand even if CVS support has not been configured (however, the
git-cvs package needs to be installed).

In addition to fixing the actual bug, this update removes the
cvsserver subcommand from git-shell by default. Refer to the updated
documentation for instructions how to reenable in case this CVS
functionality is still needed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=876854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/git"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/git"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3984"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the git packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 1:2.1.4-2.1+deb8u5.

For the stable distribution (stretch), this problem has been fixed in
version 1:2.11.0-3+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"git", reference:"1:2.1.4-2.1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"git-all", reference:"1:2.1.4-2.1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"git-arch", reference:"1:2.1.4-2.1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"git-core", reference:"1:2.1.4-2.1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"git-cvs", reference:"1:2.1.4-2.1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"git-daemon-run", reference:"1:2.1.4-2.1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"git-daemon-sysvinit", reference:"1:2.1.4-2.1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"git-doc", reference:"1:2.1.4-2.1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"git-el", reference:"1:2.1.4-2.1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"git-email", reference:"1:2.1.4-2.1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"git-gui", reference:"1:2.1.4-2.1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"git-man", reference:"1:2.1.4-2.1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"git-mediawiki", reference:"1:2.1.4-2.1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"git-svn", reference:"1:2.1.4-2.1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"gitk", reference:"1:2.1.4-2.1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"gitweb", reference:"1:2.1.4-2.1+deb8u5")) flag++;
if (deb_check(release:"9.0", prefix:"git", reference:"1:2.11.0-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"git-all", reference:"1:2.11.0-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"git-arch", reference:"1:2.11.0-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"git-core", reference:"1:2.11.0-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"git-cvs", reference:"1:2.11.0-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"git-daemon-run", reference:"1:2.11.0-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"git-daemon-sysvinit", reference:"1:2.11.0-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"git-doc", reference:"1:2.11.0-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"git-el", reference:"1:2.11.0-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"git-email", reference:"1:2.11.0-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"git-gui", reference:"1:2.11.0-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"git-man", reference:"1:2.11.0-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"git-mediawiki", reference:"1:2.11.0-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"git-svn", reference:"1:2.11.0-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"gitk", reference:"1:2.11.0-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"gitweb", reference:"1:2.11.0-3+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
