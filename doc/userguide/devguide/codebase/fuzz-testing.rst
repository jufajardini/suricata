************
Fuzz Testing
************

We use fuzzing as part of our QA suit for Suricata.

The targets can be used with libFuzzer, AFL and other fuzz platforms. If you want to debug a
CIFuzz failure, the preferred platform is OSS-Fuzz, since that is how our fuzzers are run in
our CI checks.

To enable fuzz targets compilation, add ``--enable-fuzztargets`` to configure.

.. note:: This changes various parts of Suricata, making the ``suricata`` binary
          unsafe for production use.

Running the Fuzzers
===================

1. With oss-fuzz
----------------

1.1. install docker (see https://docs.docker.com/engine/install/)

1.2. run:

```
git clone --depth 1 https://github.com/google/oss-fuzz
```
1.3. change directory into cloned repository:

```
cd oss-fuzz
```
1.4. To build Suricata docker image, run:

```
python infra/helper.py build_image suricata
```
1.5. To generate the fuzz targets, run the following command, choosing between `address` or `undefined` as sanitizer option:

```
python infra/helper.py build_fuzzers --sanitizer address suricata
```

1.6. Check what fuzz targes are available with:

```
ls build/out/suricata/fuzz_*
```
1.7. Run a fuzz target with (use ``fuzz_siginit`` or replace that with any of the available fuzz targets):

```
python infra/helper.py run_fuzzer suricata fuzz_siginit
```

1. With oss-fuzz
^^^^^^^^^^^^^^^^

* install docker
* run ::

    git clone --depth 1 https://github/google/oss-fuzz

* change directory into cloned repository ::

     cd oss-fuzz

* run ::

     python infra/helper.py build_image suricata

* run ::

     python infra/helper.py build_fuzzers --sanitizer address suricata

You can use undefined sanitizer

* run ::

     python infra/helper.py run_fuzzer suricata fuzz_siginit

 (or another fuzz target, try ``ls build/out/suricata/fuzz_*``)

To generate coverage reports:

* run ::

     python infra/helper.py build_fuzzers --sanitizer=coverage suricata

* get a corpus cf https://github.com/google/oss-fuzz/issues/2490
* put your corpus in build/corpus/suricata/<fuzz_target_name>/

* run ::

     python infra/helper.py coverage --no-corpus-download suricata

     1) edit this to clone your repo instead of OISF's: https://github.com/jufajardini/oss-fuzz/blob/master/projects/suricata/Dockerfile#L32

(remove --depth 1, to make it easier to checkout the specific branch you want, too)

2) add a line here to checkout the correct branch you're working on: https://github.com/jufajardini/oss-fuzz/blob/master/projects/suricata/build.sh#L69

Then you can follow the README I shared, the steps for oss-fuzz, and then run

$ python infra/helper.py reproduce $PROJECT_NAME <fuzz_target_name> <testcase_path>
where testcase is the failed artifact, and it should work

Reproducing issues
~~~~~~~~~~~~~~~~~~

For general guidelines on how to reproduce OSS-Fuzz issues, check:
https://google.github.io/oss-fuzz/advanced-topics/reproducing/

Suricata CIFuzz uses a rules file which is the result of concatening all ET-Open ruleset:
- Download the ET-Open ruleset:
    wget https://rules.emergingthreats.net/open/suricata/emerging.rules.zip
- extract the rules:
    unzip path/to/downloaded/rules/emerging.rules.zip
- go to the extracted directory:
    cd rules
- concatenate all rule files into one (where ``$OUT`` should be the target's directory):
    cat \*.rules > $OUT/fuzz.rules

unzip emerging.rules.zip
cd rules
cat \*.rules > $OUT/fuzz.rules (the right directory)

Oss-Fuzz
--------

| Suricata is continuously fuzz tested in OSS-Fuzz. See
| https://github.com/google/oss-fuzz/tree/master/projects/suricata

2. With libfuzzer
-----------------

To compile the fuzz targets with libFuzzer, you can do the following. These flags are just one option and you welcome to change them when you know what you are doing.

  .. code-block:: bash

     export CFLAGS="-g -O1 -fno-omit-frame-pointer -gline-tables-only \
     -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address \
     -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link"
     export CXXFLAGS="-g -O1 -fno-omit-frame-pointer -gline-tables-only \
     -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address \
     -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -stdlib=libc++"
     export RUSTFLAGS="--cfg fuzzing -Cdebuginfo=1 -Cforce-frame-pointers"
     export RUSTFLAGS="$RUSTFLAGS -Cpasses=sancov -Cllvm-args=-sanitizer-coverage-level=4 \
     -Cllvm-args=-sanitizer-coverage-trace-compares \
     -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-trace-geps \
     -Cllvm-args=-sanitizer-coverage-prune-blocks=0 -Cllvm-args=-sanitizer-coverage-pc-table \
     -Clink-dead-code -Cllvm-args=-sanitizer-coverage-stack-depth"
     export LIB_FUZZING_ENGINE=-fsanitize=fuzzer
     export CC=clang
     export CXX=clang++
     ./configure --enable-fuzztargets
     make

You can specify other sanitizers here such as ``undefined`` or ``memory``

.. note::

    Try first without exporting `RUSTFLAGS` as these seem to generate more errors.
    Once you get things to work without them, move on to trying to have the Rust side of Suricata fuzzable.
    If build fails, try removing `-stdlib=libc++` from your `CXXFLAGS` and configuring again.

Then you can run a target::

    ./src/.libs/fuzz_target_x your_libfuzzer_options

Where target_x is on file in ``ls ./src/.libs/fuzz_*``

.. note::

    If your clang does not support the compile flag ``"-fsanitize=fuzzer"`` (MacOS), you can run these same commands but you need first to install libfuzzer as libFuzzingEngine and you need to add ``export LIB_FUZZING_ENGINE=/path/to/libFuzzer.a`` before calling configure command

To compile libFuzzer, you can do the following

 .. code-block:: bash

    svn co http://llvm.org/svn/llvm-project/compiler-rt/trunk/lib/fuzzer
    cd fuzzer
    ./build.sh

3. With AFL
-----------

To compile the fuzz targets, you simply need to run

  .. code-block:: bash

    CC=afl-gcc ./configure --enable-fuzztargets
    CC=afl-gcc make

You can rather use afl-clang if needed.

Then you can run AFL as usual with each of the fuzz targets in ``./src/.libs/``

  .. code-block:: bash

    afl-fuzz your_afl_options -- ./src/.libs/fuzz_target_x @@

Extending Coverage
------------------

Adding Fuzz Targets
-------------------

For adding a new application layer protocol as target for fuzzing, modify src/tests/fuzz/confyaml.c to include the intended protocol.

The fuzz target should be created automatically with that.

