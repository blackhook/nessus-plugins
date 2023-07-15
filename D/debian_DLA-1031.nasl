#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1031-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101792);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-1000083");

  script_name(english:"Debian DLA-1031-1 : evince security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"from the Google Security Team discovered that the Evince document
viewer made insecure use of tar when opening tar comic book archives
(CBT). Opening a malicious CBT archive could result in the execution
of arbitrary code. This update disables the CBT format entirely.

For Debian 7 'Wheezy', these problems have been fixed in version
3.4.0-3.1+deb7u1.

We recommend that you upgrade your evince packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/07/msg00022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/evince"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Evince CBT File Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:evince-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:evince-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:evince-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-evince-3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libevdocument3-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libevince-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libevview3-3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (deb_check(release:"7.0", prefix:"evince", reference:"3.4.0-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"evince-common", reference:"3.4.0-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"evince-dbg", reference:"3.4.0-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"evince-gtk", reference:"3.4.0-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"gir1.2-evince-3.0", reference:"3.4.0-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libevdocument3-4", reference:"3.4.0-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libevince-dev", reference:"3.4.0-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libevview3-3", reference:"3.4.0-3.1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
