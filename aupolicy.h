/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef AUPOLICY_H
#define AUPOLICY_H

#include <bsm/libbsm.h>

#include "attrib.h"

int aupolicy_ensure(int);

#endif
