#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3501. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(89062);
  script_version("2.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-2381");
  script_xref(name:"DSA", value:"3501");

  script_name(english:"Debian DSA-3501-1 : perl - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Stephane Chazelas discovered a bug in the environment handling in
Perl. Perl provides a Perl-space hash variable, %ENV, in which
environment variables can be looked up. If a variable appears twice in
envp, only the last value would appear in %ENV, but getenv would
return the first. Perl's taint security mechanism would be applied to
the value in %ENV, but not to the other rest of the environment. This
could result in an ambiguous environment causing environment variables
to be propagated to subprocesses, despite the protections supposedly
offered by taint checking.

With this update Perl changes the behavior to match the following :

  - %ENV is populated with the first environment variable,
    as getenv would return.
  - Duplicate environment entries are removed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/perl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/perl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2016/dsa-3501"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the perl packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 5.14.2-21+deb7u3.


For the stable distribution (jessie), this problem has been fixed in
version 5.20.2-3+deb8u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"libcgi-fast-perl", reference:"5.14.2-21+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libperl-dev", reference:"5.14.2-21+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libperl5.14", reference:"5.14.2-21+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"perl", reference:"5.14.2-21+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"perl-base", reference:"5.14.2-21+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"perl-debug", reference:"5.14.2-21+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"perl-doc", reference:"5.14.2-21+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"perl-modules", reference:"5.14.2-21+deb7u3")) flag++;
if (deb_check(release:"8.0", prefix:"libperl-dev", reference:"5.20.2-3+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libperl5.20", reference:"5.20.2-3+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"perl", reference:"5.20.2-3+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"perl-base", reference:"5.20.2-3+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"perl-debug", reference:"5.20.2-3+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"perl-doc", reference:"5.20.2-3+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"perl-modules", reference:"5.20.2-3+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
