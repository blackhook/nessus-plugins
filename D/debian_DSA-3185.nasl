#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3185. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81795);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-3591", "CVE-2015-0837");
  script_bugtraq_id(73064, 73066);
  script_xref(name:"DSA", value:"3185");

  script_name(english:"Debian DSA-3185-1 : libgcrypt11 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in libgcrypt :

  - CVE-2014-3591
    The Elgamal decryption routine was susceptible to a
    side-channel attack discovered by researchers of Tel
    Aviv University. Ciphertext blinding was enabled to
    counteract it. Note that this may have a quite
    noticeable impact on Elgamal decryption performance.

  - CVE-2015-0837
    The modular exponentiation routine mpi_powm() was
    susceptible to a side-channel attack caused by
    data-dependent timing variations when accessing its
    internal pre-computed table."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-0837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libgcrypt11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2015/dsa-3185"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libgcrypt11 packages.

For the stable distribution (wheezy), these problems have been fixed
in version 1.5.0-5+deb7u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgcrypt11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"libgcrypt11", reference:"1.5.0-5+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libgcrypt11-dbg", reference:"1.5.0-5+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libgcrypt11-dev", reference:"1.5.0-5+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libgcrypt11-doc", reference:"1.5.0-5+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libgcrypt11-udeb", reference:"1.5.0-5+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
