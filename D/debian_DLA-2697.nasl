#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
# 
# Disabled on 2023/04/21 - Rejected CVE by NVD.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2697. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151192);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/18");

  script_cve_id("CVE-2021-28421");

  script_name(english:"Debian DLA-2697-1 : fluidsynth - LTS security update (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
  "This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:"
  ** REJECT ** 
  DO NOT USE THIS CANDIDATE NUMBER. 
  ConsultIDs: CVE-2021-21417. Reason: This candidate is a duplicate of CVE-2021-21417. 
  Notes: All CVE users should reference CVE-2021-21417 instead of this candidate. 
  All references and descriptions in this candidate have been removed to prevent accidental usage.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/fluidsynth");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2697");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28421");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/fluidsynth");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28421");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fluidsynth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfluidsynth-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfluidsynth1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

exit(0,'CVE-2021-28421 rejected in favor of CVE-2021-21417.');
