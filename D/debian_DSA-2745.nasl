#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2745. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(69505);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2013-1059", "CVE-2013-2148", "CVE-2013-2164", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2237", "CVE-2013-2851", "CVE-2013-2852", "CVE-2013-4162", "CVE-2013-4163");
  script_bugtraq_id(60341, 60375, 60409, 60410, 60874, 60893, 60922, 60953, 61411, 61412);
  script_xref(name:"DSA", value:"2745");

  script_name(english:"Debian DSA-2745-1 : linux - privilege escalation/denial of service/information leak");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service, information leak or privilege
escalation. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2013-1059
    Chanam Park reported an issue in the Ceph distributed
    storage system. Remote users can cause a denial of
    service by sending a specially crafted auth_reply
    message.

  - CVE-2013-2148
    Dan Carpenter reported an information leak in the
    filesystem wide access notification subsystem
    (fanotify). Local users could gain access to sensitive
    kernel memory.

  - CVE-2013-2164
    Jonathan Salwan reported an information leak in the
    CD-ROM driver. A local user on a system with a
    malfunctioning CD-ROM drive could gain access to
    sensitive memory.

  - CVE-2013-2232
    Dave Jones and Hannes Frederic Sowa resolved an issue in
    the IPv6 subsystem. Local users could cause a denial of
    service by using an AF_INET6 socket to connect to an
    IPv4 destination.

  - CVE-2013-2234
    Mathias Krause reported a memory leak in the
    implementation of PF_KEYv2 sockets. Local users could
    gain access to sensitive kernel memory.

  - CVE-2013-2237
    Nicolas Dichtel reported a memory leak in the
    implementation of PF_KEYv2 sockets. Local users could
    gain access to sensitive kernel memory.

  - CVE-2013-2851
    Kees Cook reported an issue in the block subsystem.
    Local users with uid 0 could gain elevated ring 0
    privileges. This is only a security issue for certain
    specially configured systems.

  - CVE-2013-2852
    Kees Cook reported an issue in the b43 network driver
    for certain Broadcom wireless devices. Local users with
    uid 0 could gain elevated ring 0 privileges. This is
    only a security issue for certain specially configured
    systems.

  - CVE-2013-4162
    Hannes Frederic Sowa reported an issue in the IPv6
    networking subsystem. Local users can cause a denial of
    service (system crash).

  - CVE-2013-4163
    Dave Jones reported an issue in the IPv6 networking
    subsystem. Local users can cause a denial of service
    (system crash).

This update also includes a fix for a regression in the Xen subsystem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=701744"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2013/dsa-2745"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux and user-mode-linux packages.

For the stable distribution (wheezy), these problems has been fixed in
version 3.2.46-1+deb7u1.

The following matrix lists additional source packages that were
rebuilt for compatibility with or to take advantage of this update :

                      Debian 7.0 (wheezy)  
  user-mode-linux      3.2-2um-1+deb7u2     
Note: Debian carefully tracks all known security issues across every
linux kernel package in all releases under active security support.
However, given the high frequency at which low-severity security
issues are discovered in the kernel and the resource requirements of
doing an update, updates for lower priority issues will normally not
be released for all kernels at the same time. Rather, they will be
released in a staggered or 'leap-frog' fashion."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"linux", reference:"3.2.46-1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
