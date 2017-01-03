#!/bin/bash
#
# Copyright © 2014 Intel Corporation
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice (including the next
# paragraph) shall be included in all copies or substantial portions of the
# Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.


ROOT="`dirname $0`"
ROOT="`readlink -f $ROOT/..`"
IGT_TEST_ROOT="$ROOT/tests"
RESULTS="$ROOT/results"
PIGLIT=`which piglit 2> /dev/null`

if [ ! -d "$IGT_TEST_ROOT" ]; then
	echo "Error: could not find tests directory."
	exit 1
fi

if [ ! -f "$IGT_TEST_ROOT/test-list.txt" ]; then
	echo "Error: test list not found."
	echo "Please run make in the tests directory to generate the test list."
	exit 1
fi

TEST_LIST=`cat "$IGT_TEST_ROOT/test-list.txt" | sed -e '/TESTLIST/d' -e 's/ /\n/g'`

function download_piglit {
	git clone git://anongit.freedesktop.org/piglit "$ROOT/piglit"
}

function print_help {
	echo "Usage: run-tests.sh [options]"
	echo "Available options:"
	echo "  -d              download Piglit to $ROOT/piglit"
	echo "  -h              display this help message"
	echo "  -l              list all available tests"
	echo "  -r <directory>  store the results in directory"
	echo "                  (default: $RESULTS)"
	echo "  -s              create html summary"
	echo "  -t <regex>      only include tests that match the regular expression"
	echo "                  (can be used more than once)"
	echo "  -v              enable verbose mode"
	echo "  -x <regex>      exclude tests that match the regular expression"
	echo "                  (can be used more than once)"
	echo "  -R              resume interrupted test where the partial results"
	echo "                  are in the directory given by -r"
	echo "  -n              do not retry incomplete tests when resuming a"
	echo "                  test run with -R"
	echo ""
	echo "Useful patterns for test filtering are described in the API documentation."
}

function list_tests {
	for test in $TEST_LIST; do
		SUBTESTS=`"$IGT_TEST_ROOT/$test" --list-subtests`
		if [ -z "$SUBTESTS" ]; then
			echo "$test"
		else
			for subtest in $SUBTESTS; do
				echo "$test/$subtest"
			done
		fi
	done
}

while getopts ":dhlr:st:vx:Rn" opt; do
	case $opt in
		d) download_piglit; exit ;;
		h) print_help; exit ;;
		l) list_tests; exit ;;
		r) RESULTS="$OPTARG" ;;
		s) SUMMARY="html" ;;
		t) FILTER="$FILTER -t $OPTARG" ;;
		v) VERBOSE="-v" ;;
		x) EXCLUDE="$EXCLUDE -x $OPTARG" ;;
		R) RESUME="true" ;;
		n) NORETRY="--no-retry" ;;
		:)
			echo "Option -$OPTARG requires an argument."
			exit 1
			;;
		\?)
			echo "Unknown option: -$OPTARG"
			print_help
			exit 1
			;;
	esac
done
shift $(($OPTIND-1))

if [ "x$1" != "x" ]; then
	echo "Unknown option: $1"
	print_help
	exit 1
fi

if [ "x$PIGLIT" == "x" ]; then
	PIGLIT="$ROOT/piglit/piglit"
fi

if [ ! -x "$PIGLIT" ]; then
	echo "Could not find Piglit."
	echo "Please install Piglit or use -d to download Piglit locally."
	exit 1
fi

if [ "x$RESUME" != "x" ]; then
	sudo IGT_TEST_ROOT="$IGT_TEST_ROOT" CHAMELIUM_HOST="$CHAMELIUM_HOST" "$PIGLIT" resume "$RESULTS" $NORETRY
else
	mkdir -p "$RESULTS"
	sudo IGT_TEST_ROOT="$IGT_TEST_ROOT" CHAMELIUM_HOST="$CHAMELIUM_HOST" "$PIGLIT" run igt -o "$RESULTS" -s $VERBOSE $EXCLUDE $FILTER
fi

if [ "$SUMMARY" == "html" ]; then
	"$PIGLIT" summary html --overwrite "$RESULTS/html" "$RESULTS"
	echo "HTML summary has been written to $RESULTS/html/index.html"
fi
