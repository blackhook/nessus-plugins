# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
# 
# Disabled on 2023/04/25 - Rejected CVE by NVD.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5028-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(152180);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/18");

  script_cve_id("CVE-2021-31291");
  script_xref(name:"USN", value:"5028-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 21.04 : Exiv2 vulnerability (USN-5028-1) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
  "This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
  "** REJECT ** 
  DO NOT USE THIS CANDIDATE NUMBER. 
  ConsultIDs: CVE-2021-29457. 
  Reason: This candidate is a duplicate of CVE-2021-29457. 
  Notes: All CVE users should reference CVE-2021-29457 instead of this candidate. 
  All references and descriptions in this candidate have been removed to prevent accidental usage.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5028-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31291");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libexiv2-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libexiv2-27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libexiv2-dev");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

exit(0,'CVE-2021-31291 rejected in favor of CVE-2021-29457.');
