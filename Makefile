# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright 2021 Aspeed Technology Inc.
#

all:
	for dir in */ ; do \
		if [ -d "$$dir" ] && [ -f "$$dir/Makefile" ]; then \
			make -C "$$dir" || exit 1; \
		fi; \
	done

clean:
	find . -maxdepth 1 -type d \( ! -name . \) -exec make -C {} clean \;

install:
	find . -maxdepth 1 -type d \( ! -name . \) -exec make -C {} install \;
