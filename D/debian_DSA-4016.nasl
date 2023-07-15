#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4016. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104400);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-10965", "CVE-2017-10966", "CVE-2017-15227", "CVE-2017-15228", "CVE-2017-15721", "CVE-2017-15722", "CVE-2017-15723");
  script_xref(name:"DSA", value:"4016");

  script_name(english:"Debian DSA-4016-1 : irssi - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in Irssi, a terminal
based IRC client. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2017-10965
    Brian 'geeknik' Carpenter of Geeknik Labs discovered
    that Irssi does not properly handle receiving messages
    with invalid time stamps. A malicious IRC server can
    take advantage of this flaw to cause Irssi to crash,
    resulting in a denial of service.

  - CVE-2017-10966
    Brian 'geeknik' Carpenter of Geeknik Labs discovered
    that Irssi is susceptible to a use-after-free flaw
    triggered while updating the internal nick list. A
    malicious IRC server can take advantage of this flaw to
    cause Irssi to crash, resulting in a denial of service.

  - CVE-2017-15227
    Joseph Bisch discovered that while waiting for the
    channel synchronisation, Irssi may incorrectly fail to
    remove destroyed channels from the query list, resulting
    in use after free conditions when updating the state
    later on. A malicious IRC server can take advantage of
    this flaw to cause Irssi to crash, resulting in a denial
    of service.

  - CVE-2017-15228
    Hanno Boeck reported that Irssi does not properly handle
    installing themes with unterminated colour formatting
    sequences, leading to a denial of service if a user is
    tricked into installing a specially crafted theme.

  - CVE-2017-15721
    Joseph Bisch discovered that Irssi does not properly
    handle incorrectly formatted DCC CTCP messages. A remote
    attacker can take advantage of this flaw to cause Irssi
    to crash, resulting in a denial of service.

  - CVE-2017-15722
    Joseph Bisch discovered that Irssi does not properly
    verify Safe channel IDs. A malicious IRC server can take
    advantage of this flaw to cause Irssi to crash,
    resulting in a denial of service.

  - CVE-2017-15723
    Joseph Bisch reported that Irssi does not properly
    handle overlong nicks or targets resulting in a NULL
    pointer dereference when splitting the message and
    leading to a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=867598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=879521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-10965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-10966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15227"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15228"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-10965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-10966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/irssi"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/irssi"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-4016"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the irssi packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 0.8.17-1+deb8u5.

For the stable distribution (stretch), these problems have been fixed
in version 1.0.2-1+deb9u3. CVE-2017-10965 and CVE-2017-10966 were
already fixed in an earlier point release."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:irssi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/06");
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
if (deb_check(release:"8.0", prefix:"irssi", reference:"0.8.17-1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"irssi-dbg", reference:"0.8.17-1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"irssi-dev", reference:"0.8.17-1+deb8u5")) flag++;
if (deb_check(release:"9.0", prefix:"irssi", reference:"1.0.2-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"irssi-dev", reference:"1.0.2-1+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
