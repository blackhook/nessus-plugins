#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2114. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(49676);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-2542");
  script_bugtraq_id(41891);
  script_xref(name:"DSA", value:"2114");

  script_name(english:"Debian DSA-2114-1 : git-core - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Debian stable point release 5.0.6 included updated packages of the
Git revision control system in order to fix a security issue.
Unfortunately, the update introduced a regression which could make it
impossible to clone or create Git repositories. This upgrade fixes
this regression, which is tracked as Debian bug #595728.

The original security issue allowed an attacker to execute arbitrary
code if he could trick a local user to execute a git command in a
crafted working directory (CVE-2010-2542 )."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=595728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=590026"
  );
  # https://bugs.debian.org/595728
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=595728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2010/dsa-2114"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the git-core packages.

For the stable distribution (lenny), this problem has been fixed in
version 1.5.6.5-3+lenny3.2.

The packages for the hppa architecture are not included in this
advisory. However, the hppa architecture is not known to be affected
by the regression."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-core");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"5.0", prefix:"git-arch", reference:"1.5.6.5-3+lenny3.2")) flag++;
if (deb_check(release:"5.0", prefix:"git-core", reference:"1.5.6.5-3+lenny3.2")) flag++;
if (deb_check(release:"5.0", prefix:"git-cvs", reference:"1.5.6.5-3+lenny3.2")) flag++;
if (deb_check(release:"5.0", prefix:"git-daemon-run", reference:"1.5.6.5-3+lenny3.2")) flag++;
if (deb_check(release:"5.0", prefix:"git-doc", reference:"1.5.6.5-3+lenny3.2")) flag++;
if (deb_check(release:"5.0", prefix:"git-email", reference:"1.5.6.5-3+lenny3.2")) flag++;
if (deb_check(release:"5.0", prefix:"git-gui", reference:"1.5.6.5-3+lenny3.2")) flag++;
if (deb_check(release:"5.0", prefix:"git-svn", reference:"1.5.6.5-3+lenny3.2")) flag++;
if (deb_check(release:"5.0", prefix:"gitk", reference:"1.5.6.5-3+lenny3.2")) flag++;
if (deb_check(release:"5.0", prefix:"gitweb", reference:"1.5.6.5-3+lenny3.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
