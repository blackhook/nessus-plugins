#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3435. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87742);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-7545");
  script_xref(name:"DSA", value:"3435");

  script_name(english:"Debian DSA-3435-1 : git - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Blake Burkhart discovered that the Git git-remote-ext helper
incorrectly handled recursive clones of git repositories. A remote
attacker could possibly use this issue to execute arbitary code by
injecting commands via crafted URLs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/git"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/git"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2016/dsa-3435"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the git packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 1:1.7.10.4-1+wheezy2.

For the stable distribution (jessie), this problem has been fixed in
version 1:2.1.4-2.1+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"git", reference:"1:1.7.10.4-1+wheezy2")) flag++;
if (deb_check(release:"7.0", prefix:"git-all", reference:"1:1.7.10.4-1+wheezy2")) flag++;
if (deb_check(release:"7.0", prefix:"git-arch", reference:"1:1.7.10.4-1+wheezy2")) flag++;
if (deb_check(release:"7.0", prefix:"git-core", reference:"1:1.7.10.4-1+wheezy2")) flag++;
if (deb_check(release:"7.0", prefix:"git-cvs", reference:"1:1.7.10.4-1+wheezy2")) flag++;
if (deb_check(release:"7.0", prefix:"git-daemon-run", reference:"1:1.7.10.4-1+wheezy2")) flag++;
if (deb_check(release:"7.0", prefix:"git-daemon-sysvinit", reference:"1:1.7.10.4-1+wheezy2")) flag++;
if (deb_check(release:"7.0", prefix:"git-doc", reference:"1:1.7.10.4-1+wheezy2")) flag++;
if (deb_check(release:"7.0", prefix:"git-el", reference:"1:1.7.10.4-1+wheezy2")) flag++;
if (deb_check(release:"7.0", prefix:"git-email", reference:"1:1.7.10.4-1+wheezy2")) flag++;
if (deb_check(release:"7.0", prefix:"git-gui", reference:"1:1.7.10.4-1+wheezy2")) flag++;
if (deb_check(release:"7.0", prefix:"git-man", reference:"1:1.7.10.4-1+wheezy2")) flag++;
if (deb_check(release:"7.0", prefix:"git-svn", reference:"1:1.7.10.4-1+wheezy2")) flag++;
if (deb_check(release:"7.0", prefix:"gitk", reference:"1:1.7.10.4-1+wheezy2")) flag++;
if (deb_check(release:"7.0", prefix:"gitweb", reference:"1:1.7.10.4-1+wheezy2")) flag++;
if (deb_check(release:"8.0", prefix:"git", reference:"1:2.1.4-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"git-all", reference:"1:2.1.4-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"git-arch", reference:"1:2.1.4-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"git-core", reference:"1:2.1.4-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"git-cvs", reference:"1:2.1.4-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"git-daemon-run", reference:"1:2.1.4-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"git-daemon-sysvinit", reference:"1:2.1.4-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"git-doc", reference:"1:2.1.4-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"git-el", reference:"1:2.1.4-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"git-email", reference:"1:2.1.4-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"git-gui", reference:"1:2.1.4-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"git-man", reference:"1:2.1.4-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"git-mediawiki", reference:"1:2.1.4-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"git-svn", reference:"1:2.1.4-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gitk", reference:"1:2.1.4-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gitweb", reference:"1:2.1.4-2.1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
