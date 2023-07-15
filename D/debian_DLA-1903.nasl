#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1903-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128395);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-11782", "CVE-2019-0203");

  script_name(english:"Debian DLA-1903-1 : subversion security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Subversion, a version
control system. The Common Vulnerabilities and Exposures project
identifies the following problems :

CVE-2018-11782

Ace Olszowka reported that the Subversion's svnserve server process
may exit when a well-formed read-only request produces a particular
answer, leading to a denial of service.

CVE-2019-0203

Tomas Bortoli reported that the Subversion's svnserve server process
may exit when a client sends certain sequences of protocol commands.
If the server is configured with anonymous access enabled this could
lead to a remote unauthenticated denial of service.

For Debian 8 'Jessie', these problems have been fixed in version
1.8.10-6+deb8u7.

We recommend that you upgrade your subversion packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/08/msg00037.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/subversion"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:subversion-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"libapache2-mod-svn", reference:"1.8.10-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-svn", reference:"1.8.10-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libsvn-dev", reference:"1.8.10-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libsvn-doc", reference:"1.8.10-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libsvn-java", reference:"1.8.10-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libsvn-perl", reference:"1.8.10-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libsvn-ruby1.8", reference:"1.8.10-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libsvn1", reference:"1.8.10-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"python-subversion", reference:"1.8.10-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-svn", reference:"1.8.10-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"subversion", reference:"1.8.10-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"subversion-dbg", reference:"1.8.10-6+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"subversion-tools", reference:"1.8.10-6+deb8u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
