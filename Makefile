# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright 2021 Aspeed Technology Inc.
#

all:
	find . -maxdepth 1 -type d \( ! -name . \) -exec make -C {} \;

clean:
	find . -maxdepth 1 -type d \( ! -name . \) -exec make -C {} clean \;

install:
	find . -maxdepth 1 -type d \( ! -name . \) -exec make -C {} install \;
