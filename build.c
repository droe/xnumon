/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

/*
 * Potentially volatile build information, gets rebuilt every build.
 */

#include "build.h"

const char *build_pkgname  = BUILD_PKGNAME;
const char *build_version  = BUILD_VERSION;
const char *build_date     = BUILD_DATE;
const char *build_info     = BUILD_INFO;
const char *build_features = BUILD_FEATURES;

