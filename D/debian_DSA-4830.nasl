#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4830. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(145021);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/29");

  script_cve_id("CVE-2021-21261");
  script_xref(name:"DSA", value:"4830");

  script_name(english:"Debian DSA-4830-1 : flatpak - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Simon McVittie discovered a bug in the flatpak-portal service that can
allow sandboxed applications to execute arbitrary code on the host
system (a sandbox escape).

The Flatpak portal D-Bus service (flatpak-portal, also known by its
D-Bus service name org.freedesktop.portal.Flatpak) allows apps in a
Flatpak sandbox to launch their own subprocesses in a new sandbox
instance, either with the same security settings as the caller or with
more restrictive security settings. For example, this is used in
Flatpak-packaged web browsers such as Chromium to launch subprocesses
that will process untrusted web content, and give those subprocesses a
more restrictive sandbox than the browser itself.

In vulnerable versions, the Flatpak portal service passes
caller-specified environment variables to non-sandboxed processes on
the host system, and in particular to the flatpak run command that is
used to launch the new sandbox instance. A malicious or compromised
Flatpak app could set environment variables that are trusted by the
flatpak run command, and use them to execute arbitrary code that is
not in a sandbox."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/flatpak"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/flatpak"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2021/dsa-4830"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the flatpak packages.

For the stable distribution (buster), this problem has been fixed in
version 1.2.5-0+deb10u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21261");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:flatpak");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"flatpak", reference:"1.2.5-0+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"flatpak-tests", reference:"1.2.5-0+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"gir1.2-flatpak-1.0", reference:"1.2.5-0+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libflatpak-dev", reference:"1.2.5-0+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libflatpak-doc", reference:"1.2.5-0+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libflatpak0", reference:"1.2.5-0+deb10u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
