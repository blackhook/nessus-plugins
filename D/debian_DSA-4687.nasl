#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4687. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(136676);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/21");

  script_cve_id("CVE-2020-12783");
  script_xref(name:"DSA", value:"4687");

  script_name(english:"Debian DSA-4687-1 : exim4 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It was discovered that exim4, a mail transport agent, suffers from a
authentication bypass vulnerability in the spa authentication driver.
The spa authentication driver is not enabled by default."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/exim4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/exim4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/exim4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4687"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the exim4 packages.

For the oldstable distribution (stretch), this problem has been fixed
in version 4.89-2+deb9u7.

For the stable distribution (buster), this problem has been fixed in
version 4.92-8+deb10u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"exim4", reference:"4.92-8+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"exim4-base", reference:"4.92-8+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"exim4-config", reference:"4.92-8+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"exim4-daemon-heavy", reference:"4.92-8+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"exim4-daemon-light", reference:"4.92-8+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"exim4-dev", reference:"4.92-8+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"eximon4", reference:"4.92-8+deb10u4")) flag++;
if (deb_check(release:"9.0", prefix:"exim4", reference:"4.89-2+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-base", reference:"4.89-2+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-config", reference:"4.89-2+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-daemon-heavy", reference:"4.89-2+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-daemon-heavy-dbg", reference:"4.89-2+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-daemon-light", reference:"4.89-2+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-daemon-light-dbg", reference:"4.89-2+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-dbg", reference:"4.89-2+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-dev", reference:"4.89-2+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"eximon4", reference:"4.89-2+deb9u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
