#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1335-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108769);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-1071", "CVE-2018-1083");

  script_name(english:"Debian DLA-1335-1 : zsh security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two security vulnerabilities were discovered in the Z shell.

CVE-2018-1071 Stack-based buffer overflow in the exec.c:hashcmd()
function. A local attacker could exploit this to cause a denial of
service.

CVE-2018-1083 Buffer overflow in the shell autocomplete functionality.
A local unprivileged user can create a specially crafted directory
path which leads to code execution in the context of the user who
tries to use autocomplete to traverse the before mentioned path. If
the user affected is privileged, this leads to privilege escalation.

For Debian 7 'Wheezy', these problems have been fixed in version
4.3.17-1+deb7u2.

We recommend that you upgrade your zsh packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/03/msg00038.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/zsh"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zsh-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zsh-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zsh-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zsh-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"zsh", reference:"4.3.17-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"zsh-dbg", reference:"4.3.17-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"zsh-dev", reference:"4.3.17-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"zsh-doc", reference:"4.3.17-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"zsh-static", reference:"4.3.17-1+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
