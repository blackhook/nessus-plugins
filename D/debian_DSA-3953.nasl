#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3953. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102715);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-12440");
  script_xref(name:"DSA", value:"3953");

  script_name(english:"Debian DSA-3953-1 : aodh - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Zane Bitter from Red Hat discovered a vulnerability in Aodh, the alarm
engine for OpenStack. Aodh does not verify that the user creating the
alarm is the trustor or has the same rights as the trustor, nor that
the trust is for the same project as the alarm. The bug allows that an
authenticated user without a Keystone token with knowledge of trust
IDs to perform unspecified authenticated actions by adding alarm
actions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=872605"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/aodh"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3953"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the aodh packages.

For the stable distribution (stretch), this problem has been fixed in
version 3.0.0-4+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:aodh");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/24");
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
if (deb_check(release:"9.0", prefix:"aodh-api", reference:"3.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"aodh-common", reference:"3.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"aodh-doc", reference:"3.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"aodh-evaluator", reference:"3.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"aodh-expirer", reference:"3.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"aodh-listener", reference:"3.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"aodh-notifier", reference:"3.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python-aodh", reference:"3.0.0-4+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
