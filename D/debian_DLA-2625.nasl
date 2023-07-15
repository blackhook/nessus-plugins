#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2625-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(148610);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id("CVE-2021-28374");

  script_name(english:"Debian DLA-2625-1 : courier-authlib security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Debian courier-authlib package before 0.71.1-2 for Courier
Authentication Library creates a /run/courier/authdaemon directory
with weak permissions, allowing an attacker to read user information.
This may include a cleartext password in some configurations. In
general, it includes the user's existence, uid and gids, home and/or
Maildir directory, quota, and some type of password information (such
as a hash).

For Debian 9 stretch, this problem has been fixed in version
0.66.4-9+deb9u1.

We recommend that you upgrade your courier-authlib packages.

For the detailed security status of courier-authlib please refer to
its security tracker page at:
https://security-tracker.debian.org/tracker/courier-authlib

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/04/msg00011.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/courier-authlib"
  );
  # https://security-tracker.debian.org/tracker/source-package/courier-authlib
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3247ad46"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:courier-authdaemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:courier-authlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:courier-authlib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:courier-authlib-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:courier-authlib-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:courier-authlib-pipe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:courier-authlib-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:courier-authlib-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:courier-authlib-userdb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/15");
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
if (deb_check(release:"9.0", prefix:"courier-authdaemon", reference:"0.66.4-9+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"courier-authlib", reference:"0.66.4-9+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"courier-authlib-dev", reference:"0.66.4-9+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"courier-authlib-ldap", reference:"0.66.4-9+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"courier-authlib-mysql", reference:"0.66.4-9+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"courier-authlib-pipe", reference:"0.66.4-9+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"courier-authlib-postgresql", reference:"0.66.4-9+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"courier-authlib-sqlite", reference:"0.66.4-9+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"courier-authlib-userdb", reference:"0.66.4-9+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
